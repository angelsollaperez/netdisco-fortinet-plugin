package App::NetdiscoX::Worker::Plugin::Discover::PortProperties::FortinetPortProperties;

use Dancer ':syntax';
use App::Netdisco::Worker::Plugin;
use aliased 'App::Netdisco::Worker::Status';

use App::Netdisco::Transport::SNMP ();
use Dancer::Plugin::DBIC 'schema';

use Encode;
use App::Netdisco::Util::Web 'sort_port';
use App::Netdisco::Util::Permission 'acl_matches';
use App::Netdisco::Util::PortAccessEntity 'update_pae_attributes';
use App::Netdisco::Util::FastResolver 'hostnames_resolve_async';
use App::Netdisco::Util::Device qw/is_discoverable match_to_setting/;

use LWP::UserAgent;
use HTTP::Request::Common;
use JSON qw(decode_json);

# -------------------------------------------------------------
# Custom API call function
# -------------------------------------------------------------
# Function to fetch LLDP data via API
sub fetch_lldp_data_api {
    my ($device_ip, $user, $password) = @_;
    
    my $cookie_jar = {};
    my $ua = LWP::UserAgent->new(
        cookie_jar => $cookie_jar,
        ssl_opts => { SSL_verify_mode => 0, verify_hostname => 0 });

    $ua->timeout(10);

    # Login
    my $login_url = "https://$device_ip/logincheck";
    my $response = $ua->post($login_url, {
        username => $user,
        secretkey => $password,
    });

    if (!$response->is_success) {
        warn "Login failed: " . $response->status_line;
        return;
    }

    # Fetch LLDP data
    my $lldp_url = "https://$device_ip/api/v2/monitor/switch/lldp-state";
    $response = $ua->get($lldp_url);

    if ($response->is_success) {
        my $data = decode_json($response->content);
    }

    if (!$response->is_success) {
        warn "Failed to fetch LLDP data: " . $response->status_line;
        return;
    }

    return decode_json($response->content);
}


register_worker({ phase => 'main', driver => 'snmp', priority => 1000 }, sub {
  my ($job, $workerconf) = @_;

  my $device = $job->device;
  return unless $device->in_storage;
  return unless $device->vendor =~ /fortinet/i;

  my $snmp = App::Netdisco::Transport::SNMP->reader_for($device)
    or return Status->defer("discover failed: could not SNMP connect to $device");

  my $interfaces = $snmp->interfaces || {};
  my %properties = ();

  # cache the device ports to save hitting the database for many single rows
  my $device_ports = vars->{'device_ports'}
    || { map {($_->port => $_)} $device->ports->all };

  my @remote_ips = map {{ip => $_->remote_ip, port => $_->port}}
                   grep {$_->remote_ip}
                   values %$device_ports;

  debug sprintf ' [%s] resolving %d remote_ips with max %d outstanding requests',
      $device->ip, scalar @remote_ips, $ENV{'PERL_ANYEVENT_MAX_OUTSTANDING_DNS'};

  my $resolved_remote_ips = hostnames_resolve_async(\@remote_ips);
  $properties{ $_->{port} }->{remote_dns} = $_->{dns} for @$resolved_remote_ips;

  my $raw_speed = $snmp->i_speed_raw || {};

  foreach my $idx (keys %$raw_speed) {
    my $port = $interfaces->{$idx} or next;
    if (!defined $device_ports->{$port}) {
        debug sprintf ' [%s] properties/speed - local port %s already skipped, ignoring',
          $device->ip, $port;
        next;
    }

    $properties{ $port }->{raw_speed} = $raw_speed->{$idx};
  }

  my $err_cause = $snmp->i_err_disable_cause || {};

  foreach my $idx (keys %$err_cause) {
    my $port = $interfaces->{$idx} or next;
    if (!defined $device_ports->{$port}) {
        debug sprintf ' [%s] properties/errdis - local port %s already skipped, ignoring',
          $device->ip, $port;
        next;
    }

    $properties{ $port }->{error_disable_cause} = $err_cause->{$idx};
  }

  my $faststart = $snmp->i_faststart_enabled || {};

  foreach my $idx (keys %$faststart) {
    my $port = $interfaces->{$idx} or next;
    if (!defined $device_ports->{$port}) {
        debug sprintf ' [%s] properties/faststart - local port %s already skipped, ignoring',
          $device->ip, $port;
        next;
    }

    $properties{ $port }->{faststart} = $faststart->{$idx};
  }

  my $c_if  = $snmp->c_if  || {};
  my $c_cap = $snmp->c_cap || {};
  my $c_port = $snmp->c_port || {};
  my $c_platform = $snmp->c_platform || {};

  my $rem_media_cap = $snmp->lldp_media_cap || {};
  my $rem_vendor = $snmp->lldp_rem_vendor || {};
  my $rem_model  = $snmp->lldp_rem_model  || {};
  my $rem_os_ver = $snmp->lldp_rem_sw_rev || {};
  my $rem_serial = $snmp->lldp_rem_serial || {};
   
  # -------------------------------------------------------------
  # Get API creds from the config
  # -------------------------------------------------------------
  my $device_auth = config->{'device_auth'};
  my ($fortinet_auth) = grep { $_->{tag} eq 'fortinet_api_credentials' } @$device_auth;
  my $api_username = $fortinet_auth->{username};
  my $api_password = $fortinet_auth->{password};

  # remap using api response
  my $api_data_lldp = fetch_lldp_data_api($device->ip, $api_username, $api_password) || {};
  my %port_mapping;

  if (defined $api_data_lldp->{results} && ref($api_data_lldp->{results}) eq 'ARRAY') {
    foreach my $result (@{$api_data_lldp->{results}}) {
        next unless $result->{port} && $result->{port_id} && $result->{system_name};
        my $snmp_port = $result->{port_id};
        $snmp_port =~ s/ \(ifname\)$//;
        $snmp_port =~ s/ \(mac\)$//;
        my $unique_key = $result->{system_name} . "|" . $snmp_port;
        my $port_number = $result->{port};
        $port_number =~ s/^port//i;
        $port_mapping{$unique_key} = $port_number;
    }

    # Update c_if and c_port
    foreach my $key (keys %{$c_if}) {
        my $snmp_port = $c_port->{$key};
        foreach my $mapping_key (keys %port_mapping) {
            my ($system_name, $mapped_snmp_port) = split /\|/, $mapping_key;
            if ($mapped_snmp_port eq $snmp_port) {
                my $local_port = $port_mapping{$mapping_key};
                $c_if->{$key} = $local_port;
                $c_port->{$key} = $mapped_snmp_port;
                last;
            }
        }
    }
  }

  foreach my $idx (keys %$c_if) {
    my $port = $interfaces->{ $c_if->{$idx} } or next;
    if (!defined $device_ports->{$port}) {
        debug sprintf ' [%s] properties/lldpcap - local port %s already skipped, ignoring',
          $device->ip, $port;
        next;
    }

    my $remote_cap  = $c_cap->{$idx} || [];
    my $remote_type = Encode::decode('UTF-8', $c_platform->{$idx} || '');

    $properties{ $port }->{remote_is_wap} = 'false';
    $properties{ $port }->{remote_is_phone} = 'false';
    $properties{ $port }->{remote_is_discoverable} = 'true';

    if (scalar grep {match_to_setting($_, 'wap_capabilities')} @$remote_cap
        or match_to_setting($remote_type, 'wap_platforms')) {

        $properties{ $port }->{remote_is_wap} = 'true';
        debug sprintf ' [%s] properties/lldpcap - remote on port %s is a WAP',
          $device->ip, $port;
    }

    if (scalar grep {match_to_setting($_, 'phone_capabilities')} @$remote_cap
        or match_to_setting($remote_type, 'phone_platforms')) {

        $properties{ $port }->{remote_is_phone} = 'true';
        debug sprintf ' [%s] properties/lldpcap - remote on port %s is a Phone',
          $device->ip, $port;
    }

    if (! is_discoverable($device_ports->{$port}->remote_ip, $remote_type, $remote_cap)) {

        $properties{ $port }->{remote_is_discoverable} = 'false';
        debug sprintf ' [%s] properties/lldpcap - remote on port %s is denied discovery',
          $device->ip, $port;
    }

    next unless scalar grep {defined && m/^inventory$/} @{ $rem_media_cap->{$idx} };

    $properties{ $port }->{remote_vendor} = $rem_vendor->{ $idx };
    $properties{ $port }->{remote_model}  = $rem_model->{ $idx };
    $properties{ $port }->{remote_os_ver} = $rem_os_ver->{ $idx };
    $properties{ $port }->{remote_serial} = $rem_serial->{ $idx };
  }

  if (scalar @{ setting('ignore_deviceports') }) {
    foreach my $map (@{ setting('ignore_deviceports')}) {
        next unless ref {} eq ref $map;

        foreach my $key (sort keys %$map) {
            # lhs matches device, rhs matches port
            next unless $key and $map->{$key};
            next unless acl_matches($device, $key);

            foreach my $port (sort { sort_port($a, $b) } keys %properties) {
                next unless acl_matches([$properties{$port}, $device_ports->{$port}],
                                        $map->{$key});

                debug sprintf ' [%s] properties - removing %s (config:ignore_deviceports)',
                  $device->ip, $port;
                $device_ports->{$port}->delete; # like, for real, in the DB
                delete $properties{$port};
            }
        }
    }
  }

  foreach my $idx (keys %$interfaces) {
    next unless defined $idx;
    my $port = $interfaces->{$idx} or next;

    if (!defined $device_ports->{$port}) {
        debug sprintf ' [%s] properties/ifindex - local port %s already skipped, ignoring',
          $device->ip, $port;
        next;
    }

    if ($idx !~ m/^[0-9]+$/) {
        debug sprintf ' [%s] properties/ifindex - port %s ifindex %s is not an integer',
          $device->ip, $port, $idx;
        next;
    }

    $properties{ $port }->{ifindex} = $idx;
  }

  return Status->info(" [$device] no port properties to record")
    unless scalar keys %properties;

  schema('netdisco')->txn_do(sub {
    my $gone = $device->properties_ports->delete;

    debug sprintf ' [%s] properties - removed %d port properties',
      $device->ip, $gone;

    $device->properties_ports->populate(
      [map {{ port => $_, %{ $properties{$_} } }} keys %properties] );

    debug sprintf ' [%s] properties - updating Port Access Entity', $device->ip;
    update_pae_attributes($device);

    return Status->done(sprintf ' [%s] properties - added %d new port properties',
      $device->ip, scalar keys %properties);
  });

});

true;
