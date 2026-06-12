package App::NetdiscoX::Worker::Plugin::Discover::VLANs::FortinetVlans;

use Dancer ':syntax';
use Dancer::Plugin::DBIC;
use App::Netdisco::Worker::Plugin;
use App::Netdisco::Transport::SNMP;
use App::Netdisco::Util::Device 'get_device';
use aliased 'App::Netdisco::Worker::Status';
use List::MoreUtils 'uniq';
use LWP::UserAgent;
use JSON qw(decode_json);


use strict;
use warnings;
use Exporter;
use SNMP::Info;
@SNMP::Info::Bridge::ISA       = qw/SNMP::Info Exporter/;
@SNMP::Info::Bridge::EXPORT_OK = qw//;


my %FUNCS = (
    'bp_index'       => 'dot1dBasePortIfIndex',
    'qb_i_vlan'      => 'dot1qPvid',
    'qb_cv_egress'   => 'dot1qVlanCurrentEgressPorts',
    'qb_cv_untagged' => 'dot1qVlanCurrentUntaggedPorts',
    'qb_v_egress'    => 'dot1qVlanStaticEgressPorts',
    'qb_v_untagged'  => 'dot1qVlanStaticUntaggedPorts',
);

my %MUNGE = (
    %SNMP::Info::MUNGE,
    'qb_cv_egress'   => \&SNMP::Info::munge_port_list,
    'qb_cv_untagged' => \&SNMP::Info::munge_port_list,
    'qb_v_egress'    => \&SNMP::Info::munge_port_list,
    'qb_v_untagged'  => \&SNMP::Info::munge_port_list,
);

# -------------------------------------------------------------
# SNMP helpers (native VLAN + static membership)
# -------------------------------------------------------------

sub i_vlan_plugin {
    my $bridge  = shift;
    my $partial = shift;

    my $i_pvid = $bridge->qb_i_vlan($partial) || {};

    my $i_vlan = {};
    foreach my $port (keys %$i_pvid) {
        $i_vlan->{$port} = $i_pvid->{$port};
    }
    return $i_vlan;
}

sub i_untagged_plugin { goto &i_vlan_plugin }

sub map_vlan_id_to_name {
    my ($v_name, $vlan_id) = @_;
    return $v_name->{$vlan_id} || $vlan_id;
}

sub i_vlan_membership_plugin {
    my $bridge  = shift;
    my $partial = shift;
    my $v_name  = shift;

    my $v_ports = $bridge->qb_cv_egress() || $bridge->qb_v_egress();
    my $result  = _vlan_hoa_plugin($bridge, $v_ports, $partial);

    my %mapped_result;
    foreach my $port (keys %$result) {
        $mapped_result{$port} = [
            map { map_vlan_id_to_name($v_name, $_) } @{ $result->{$port} }
        ];
    }
    return \%mapped_result;
}

sub i_vlan_membership_untagged_plugin {
    my $bridge  = shift;
    my $partial = shift;
    my $v_name  = shift;

    my $v_ports = $bridge->qb_cv_untagged() || $bridge->qb_v_untagged();
    my $result  = _vlan_hoa_plugin($bridge, $v_ports, $partial);

    my %mapped_result;
    foreach my $port (keys %$result) {
        $mapped_result{$port} = [
            map { map_vlan_id_to_name($v_name, $_) } @{ $result->{$port} }
        ];
    }
    return \%mapped_result;
}

sub _vlan_hoa_plugin {
    my $bridge = shift;
    my ($v_ports, $partial) = @_;

    my $vlan_hoa = {};
    foreach my $idx (keys %$v_ports) {
        next unless defined $v_ports->{$idx};
        my $portlist = $v_ports->{$idx};

        (my $vlan = $idx) =~ s/^(\d+\.)*//g;

        for (my $i = 0; $i <= $#$portlist; $i++) {
            if (@$portlist[$i]) {
                my $port_number = $i + 1;
                push(@{ $vlan_hoa->{$port_number} }, $vlan);
            }
        }
    }
    return $vlan_hoa;
}

# -------------------------------------------------------------
# FortiSwitch REST helpers (switch/mac-address on the FortiSwitch IP)
# -------------------------------------------------------------

sub _vlan_number {
    my $value = shift;
    return unless defined $value;
    return int($1) if "$value" =~ /^\s*(\d+)\s*$/;
    return int($1) if "$value" =~ /vlan\s*([0-9]+)/i;
    return;
}

sub _normalize_identity {
    my $value = shift;
    return unless defined $value;
    $value = lc "$value";
    $value =~ s/^\s+|\s+$//g;
    $value =~ s/[^a-z0-9.]//g;
    return length $value ? $value : undef;
}

sub _normalize_port_key {
    my $value = shift;
    return unless defined $value;
    $value = lc "$value";
    $value =~ s/\s+//g;
    $value =~ s/\(.*?\)$//;
    return length $value ? $value : undef;
}

sub _device_value {
    my ($device, $method) = @_;
    return unless $device && $device->can($method);
    my $value = eval { $device->$method };
    return $value if defined $value && length "$value";
    return;
}

sub _device_identities {
    my $device = shift;
    my %ids;
    foreach my $m (qw(ip name dns serial mac)) {
        my $v = _device_value($device, $m);
        next unless defined $v && length "$v";
        my $n = _normalize_identity($v);
        $ids{$n} = 1 if defined $n;
    }
    return \%ids;
}

sub _build_port_lookup {
    my $device_ports = shift || {};
    my %lookup;

    foreach my $port (keys %$device_ports) {
        $lookup{$port}     ||= $port;
        $lookup{lc $port}  ||= $port;

        my $normalized = _normalize_port_key($port);
        $lookup{$normalized} ||= $port if $normalized;

        if ($port =~ /^port(\d+)$/i) {
            $lookup{$1} ||= $port;
        }
    }
    return \%lookup;
}

sub _resolve_device_port {
    my ($port_lookup, $api_port) = @_;
    return unless defined $api_port;

    return $port_lookup->{$api_port}
        || $port_lookup->{ lc "$api_port" }
        || $port_lookup->{ _normalize_port_key($api_port) };
}

sub _fortinet_api_credentials {
    my $device_auth = config->{'device_auth'} || [];
    my ($fortinet_auth) = grep {
        ref $_ eq 'HASH'
            && defined $_->{tag}
            && $_->{tag} eq 'fortinet_api_credentials'
    } @$device_auth;

    return unless $fortinet_auth;

    my $api_host = $fortinet_auth->{fortigate_url}
        || $fortinet_auth->{fortigate_ip}
        || $fortinet_auth->{fortigate_host}
        || $fortinet_auth->{host}
        || $fortinet_auth->{ip};

    if ($api_host && $fortinet_auth->{port}
        && $api_host !~ m{:\d+(?:/)?$}
        && $api_host !~ m{^https?://[^/]+:\d+}i) {
        $api_host .= ':' . $fortinet_auth->{port};
    }

    return (
        $api_host,
        $fortinet_auth->{username},
        $fortinet_auth->{password},
        ($fortinet_auth->{token} || $fortinet_auth->{api_token}),
        $fortinet_auth->{vdom},
    );
}

sub _fortinet_base_url {
    my $host = shift;
    return unless defined $host && length "$host";
    $host =~ s{/$}{};
    return $host if $host =~ m{^https?://}i;
    return "https://$host";
}

sub _fortigate_login {
    my ($ua, $base_url, $user, $password, $token, $diag) = @_;

    if ($token) {
        $ua->default_header(Authorization => "Bearer $token");
        return 1;
    }

    my $login = $ua->post("$base_url/logincheck", {
        username  => $user,
        secretkey => $password,
        ajax      => 1,
    });
    unless ($login->is_success) {
        $diag->{login_status} = $login->status_line;
        debug sprintf ' [FortinetVlans API] login to %s failed: %s',
            $base_url, $login->status_line;
        return 0;
    }
    my $body = $login->decoded_content // '';
    if (substr($body, 0, 1) eq '0') {
        $diag->{login_status} = 'rejected(body=0)';
        debug sprintf ' [FortinetVlans API] login to %s rejected (body starts with 0)',
            $base_url;
        return 0;
    }

    my $csrf;
    $ua->cookie_jar->scan(sub {
        my (undef, $key, $val) = @_;
        $csrf = $val if $key && $key =~ /^ccsrftoken/ && !defined $csrf;
    });
    if (defined $csrf) {
        $csrf =~ s/^"|"$//g;
        $ua->default_header('X-CSRFTOKEN' => $csrf) if length $csrf;
    }
    $diag->{login_status} = 'ok';
    return 1;
}

sub _fortigate_get_results {
    my ($ua, $base_url, $path, $diag, $diag_key) = @_;

    my $r = $ua->get("$base_url$path");
    $diag->{$diag_key} = $r->code if $diag_key;
    unless ($r->is_success) {
        debug sprintf ' [FortinetVlans API] GET %s failed: %s', $path, $r->status_line;
        return;
    }
    my $data = eval { decode_json($r->content) };
    if ($@) {
        debug sprintf ' [FortinetVlans API] JSON decode failed for %s: %s', $path, $@;
        return;
    }
    return unless ref $data eq 'HASH';
    my $res = $data->{results};
    return [] unless ref $res eq 'ARRAY';
    return $res;
}

# FortiSwitch local REST: /api/v2/monitor/switch/mac-address
# Returns the operational VLAN each MAC is learned on (post-NAC),
# reachable directly on the FortiSwitch IP (no FortiGate firewall).
sub fetch_fortiswitch_mac_table {
    my ($device_ip, $user, $password, $token, $diag) = @_;
    $diag ||= {};
    return unless $device_ip && (($user && defined $password) || $token);

    my $base_url = _fortinet_base_url($device_ip) or return;

    my $ua = LWP::UserAgent->new(
        cookie_jar => {},
        ssl_opts   => { SSL_verify_mode => 0, verify_hostname => 0 },
    );
    $ua->timeout(15);

    return unless _fortigate_login($ua, $base_url, $user, $password, $token, $diag);

    return _fortigate_get_results($ua, $base_url,
        '/api/v2/monitor/switch/mac-address', $diag, 'http_status');
}

# Skip interfaces that are not access ports (FortiLink trunks, internal).
sub _is_skippable_interface {
    my $iface = shift;
    return 1 unless defined $iface && length $iface;
    return 1 if $iface =~ /^_/;            # _FlInK*, internal-ish
    return 1 if lc($iface) eq 'internal';
    return 0;
}

# Skip entries we must not treat as dynamic port auth:
#  - trunk-learned MACs (uplink traffic)
#  - entries without the 'used' flag (stale static entries)
sub _is_skippable_entry {
    my $entry = shift;
    return 1 unless ref $entry eq 'HASH';
    return 1 if _is_skippable_interface($entry->{interface});

    my $flags = $entry->{flags} // '';
    return 1 if $flags =~ /trunk/i;
    return 1 unless $flags =~ /used/i;
    return 0;
}

sub _apply_dynamic_vlan_overrides {
    my ($device, $device_ports, $portvlans, $p_seen) = @_;

    my $diag = vars->{'fortinet_vlan_diag'} ||= {};
    $diag->{host}       = $device->ip;
    $diag->{status}     = '';
    $diag->{switch_ids} = 'self';

    my (undef, $api_user, $api_password, $api_token) = _fortinet_api_credentials();

    unless (($api_user && defined $api_password) || $api_token) {
        $diag->{status} = 'no_creds';
        debug sprintf ' [%s] FortinetVlans dynamic VLAN: no credentials in fortinet_api_credentials, skipping',
            $device->ip;
        return 0;
    }

    my $entries = fetch_fortiswitch_mac_table(
        $device->ip, $api_user, $api_password, $api_token, $diag,
    );
    unless (ref $entries eq 'ARRAY' && @$entries) {
        $diag->{status} ||= 'empty_or_failed';
        $diag->{total} = ref $entries eq 'ARRAY' ? scalar @$entries : 0;
        debug sprintf ' [%s] FortinetVlans dynamic VLAN: empty mac-address response',
            $device->ip;
        return 0;
    }
    $diag->{total} = scalar @$entries;

    my $port_lookup = _build_port_lookup($device_ports);

    my %port_vlans;
    my %port_sample_mac;
    my $considered = 0;
    my $skipped    = 0;

    foreach my $entry (@$entries) {
        if (_is_skippable_entry($entry)) {
            ++$skipped;
            next;
        }
        ++$considered;

        my $api_port = $entry->{interface} // $entry->{port} // $entry->{port_name};
        my $vlan     = _vlan_number($entry->{vlan} // $entry->{vlan_id} // $entry->{vlanid});
        next unless defined $api_port && $vlan;

        my $port = _resolve_device_port($port_lookup, $api_port) or next;

        $port_vlans{$port}{$vlan}++;
        $port_sample_mac{$port} //= (
            $entry->{mac} // $entry->{mac_address} // $entry->{'mac-address'}
        );
    }

    $diag->{matched}            = $considered;
    $diag->{ports_with_dynamic} = scalar keys %port_vlans;

    debug sprintf ' [%s] FortinetVlans mac-address: total=%d considered=%d skipped=%d ports=%d',
        $device->ip, scalar @$entries, $considered, $skipped, scalar keys %port_vlans;

    unless (keys %port_vlans) {
        $diag->{status} ||= 'no_port_match';
        return 0;
    }

    my $updated = 0;
    my @picks;

    foreach my $port (sort keys %port_vlans) {
        my @vlans = sort {
            $port_vlans{$port}{$b} <=> $port_vlans{$port}{$a}
                || $a <=> $b
        } keys %{ $port_vlans{$port} };
        next unless @vlans;

        my $dynamic_vlan = $vlans[0];

        my @existing = grep { $_->{port} eq $port } @$portvlans;
        my $vlantype = @existing ? $existing[0]->{vlantype} : undef;

        @$portvlans = grep { $_->{port} ne $port } @$portvlans;

        push @$portvlans, {
            port          => $port,
            vlan          => $dynamic_vlan,
            native        => 't',
            egress_tag    => 'f',
            vlantype      => $vlantype,
            last_discover => \'LOCALTIMESTAMP',
        };
        ++$p_seen->{$dynamic_vlan};
        ++$updated;

        push @picks, "$port:$dynamic_vlan";
        my $cand_summary = join(',', map { "${_}x$port_vlans{$port}{$_}" } @vlans);
        debug sprintf ' [%s] FortinetVlans dynamic membership override: port=%s picked=%s candidates=[%s] mac=%s source=fortiswitch_rest',
            $device->ip, $port, $dynamic_vlan, $cand_summary,
            ($port_sample_mac{$port} // '');
    }

    $diag->{updated} = $updated;
    $diag->{picks}   = \@picks;
    $diag->{status}  = 'ok';

    return $updated;
}

# -------------------------------------------------------------
# Main plugin
# -------------------------------------------------------------

register_worker({ phase => 'main', driver => 'snmp', priority => 1000 }, sub {
  my ($job, $workerconf) = @_;

  my $device = $job->device;
  return unless $device->in_storage;
  return unless $device->vendor =~ /fortinet/i;

  debug sprintf ' [%s] FortinetVlans plugin is running', $device->ip;

  my $snmp = App::Netdisco::Transport::SNMP->reader_for($device)
    or return Status->defer("discover failed: could not SNMP connect to $device");

  my $v_name = $snmp->v_name || {};

  my %copy = %$v_name;
  my $v_index = \%copy;

  foreach my $key (keys %$v_name) {
    $v_index->{$key} =~ s/vlan//;
    $v_index->{$key} = $v_index->{$key} =~ /(\d+)/ ? $1 : '0';
  }

  my $device_ports = vars->{'device_ports'}
    || { map { ($_->port => $_) } $device->ports->all };

  my $i_vlan_type = $snmp->i_vlan_type;
  my $interfaces  = $snmp->interfaces;

  my $i_vlan                     = i_vlan_plugin($snmp);
  my $i_vlan_membership          = i_vlan_membership_plugin($snmp, undef, $v_index);
  my $i_vlan_membership_untagged = i_vlan_membership_untagged_plugin($snmp, undef, $v_index);

  my %p_seen    = ();
  my @portvlans = ();
  my @active_ports = uniq(keys %$i_vlan_membership_untagged, keys %$i_vlan_membership);

  foreach my $entry (@active_ports) {
    my $port = $interfaces->{$entry} or next;

    if (!defined $device_ports->{$port}) {
      debug sprintf ' [%s] vlans - local port %s already skipped, ignoring',
        $device->ip, $port;
      next;
    }

    my %this_port_vlans = ();
    my $type = $i_vlan_type->{$entry};

    foreach my $vlan (@{ $i_vlan_membership_untagged->{$entry} || [] }) {
      next unless $vlan;
      next if $this_port_vlans{$vlan};
      my $native = ((defined $i_vlan->{$entry})
                      and ($vlan eq $i_vlan->{$entry})) ? 't' : 'f';

      push @portvlans, {
          port          => $port,
          vlan          => $vlan,
          native        => $native,
          egress_tag    => 'f',
          vlantype      => $type,
          last_discover => \'LOCALTIMESTAMP',
      };
      ++$this_port_vlans{$vlan};
      ++$p_seen{$vlan};
    }

    foreach my $vlan (@{ $i_vlan_membership->{$entry} || [] }) {
      next unless $vlan;
      next if $this_port_vlans{$vlan};
      my $native = ((defined $i_vlan->{$entry})
                      and ($vlan eq $i_vlan->{$entry})) ? 't' : 'f';

      push @portvlans, {
          port          => $port,
          vlan          => $vlan,
          native        => $native,
          egress_tag    => ($native eq 't' ? 'f' : 't'),
          vlantype      => $type,
          last_discover => \'LOCALTIMESTAMP',
      };
      ++$this_port_vlans{$vlan};
      ++$p_seen{$vlan};
    }
  }

  my $dynamic_updated = eval {
    _apply_dynamic_vlan_overrides($device, $device_ports, \@portvlans, \%p_seen);
  };
  if ($@) {
    debug sprintf ' [%s] FortinetVlans dynamic VLAN override failed (non-fatal): %s',
      $device->ip, $@;
  }
  else {
    debug sprintf ' [%s] FortinetVlans dynamic VLAN override updated %d ports',
      $device->ip, ($dynamic_updated || 0);
  }

  foreach my $port (keys %$interfaces) {
    my $native_vlan = $i_vlan->{$port} // undef;

    schema('netdisco')->txn_do(sub {
        my $device_port = schema('netdisco')->resultset('DevicePort')->find_or_create({
            ip   => $device->ip,
            port => $interfaces->{$port},
        });
        if ($device_port) {
            $device_port->update({ vlan => $native_vlan });
        }
    });
  }

  if (@portvlans) {
    schema('netdisco')->txn_do(sub {
      my $gone = $device->port_vlans->delete;
      debug sprintf ' [%s] vlans - removed %d port VLANs', $device->ip, $gone;
      $device->port_vlans->populate(\@portvlans);
      debug sprintf ' [%s] vlans - added %d new port VLANs',
        $device->ip, scalar @portvlans;
    });
  }
  else {
    debug sprintf ' [%s] vlans - no port VLANs discovered, keeping existing port VLANs',
      $device->ip;
  }

  my %d_seen      = ();
  my @devicevlans = ();

  my $add_device_vlan = sub {
      my ($vlan, $description) = @_;
      $vlan = _vlan_number($vlan);
      return unless $vlan;
      return if $d_seen{$vlan}++;

      push @devicevlans, {
          vlan          => $vlan,
          description   => $description || (sprintf "VLAN %d", $vlan),
          last_discover => \'LOCALTIMESTAMP',
      };
  };

  foreach my $entry (keys %$v_name) {
      my $vlan = $v_index->{$entry};
      $add_device_vlan->($vlan, $v_name->{$entry});
  }

  foreach my $vlan (keys %p_seen) {
      $add_device_vlan->($vlan);
  }

  foreach my $row (@portvlans) {
      $add_device_vlan->($row->{vlan});
  }

  foreach my $vlan (values %{ $i_vlan || {} }) {
      $add_device_vlan->($vlan);
  }

  unless (@devicevlans) {
      my @fallback_portvlans = @portvlans;
      if (!@fallback_portvlans) {
          @fallback_portvlans = map {{
              vlan => eval { $_->vlan },
          }} eval { $device->port_vlans->all };
      }
      foreach my $row (@fallback_portvlans) {
          $add_device_vlan->($row->{vlan});
      }
      debug sprintf ' [%s] FortinetVlans device VLAN fallback added %d VLANs',
        $device->ip, scalar @devicevlans;
  }

  vars->{'hook_data'}->{'vlans'} = \@devicevlans;

  if (@devicevlans) {
    schema('netdisco')->txn_do(sub {
      my @devicevlans_with_ip = map {{
        ip => $device->ip,
        %{$_},
      }} @devicevlans;

      my $direct_error;
      my $gone = eval {
        my $device_vlans = schema('netdisco')->resultset('DeviceVlan');
        my $deleted = $device_vlans->search({ip => $device->ip})->delete;
        $device_vlans->populate(\@devicevlans_with_ip);
        $deleted;
      };
      $direct_error = $@;

      if ($direct_error) {
        debug sprintf ' [%s] vlans - direct DeviceVlan update failed, using relation fallback: %s',
          $device->ip, $direct_error;
        $gone = $device->vlans->delete;
        $device->vlans->populate(\@devicevlans);
      }

      debug sprintf ' [%s] vlans - removed %d device VLANs',
        $device->ip, ($gone || 0);
      debug sprintf ' [%s] vlans - added %d new device VLANs',
        $device->ip, scalar @devicevlans;
    });
  }
  else {
    debug sprintf ' [%s] vlans - no device VLANs discovered, keeping existing device VLANs',
      $device->ip;
  }

  my $d = vars->{'fortinet_vlan_diag'} || {};
  my $picks_str = '';
  if (ref $d->{picks} eq 'ARRAY' && @{ $d->{picks} }) {
      my @show = @{ $d->{picks} };
      my $extra = '';
      if (@show > 6) {
          $extra = sprintf ',...+%d', (scalar @show - 6);
          @show = @show[0..5];
      }
      $picks_str = ' picks=[' . join(',', @show) . $extra . ']';
  }

  my $summary = sprintf
      'fortiswitch_rest host=%s login=%s http=%s status=%s switch_ids=[%s] total=%s considered=%s ports=%s updated=%s%s',
      ($d->{host}             // '-'),
      ($d->{login_status}     // '-'),
      (defined $d->{http_status} ? $d->{http_status} : '-'),
      ($d->{status}           // '-'),
      ($d->{switch_ids}       // '-'),
      (defined $d->{total}    ? $d->{total} : '-'),
      (defined $d->{matched}  ? $d->{matched} : '-'),
      (defined $d->{ports_with_dynamic} ? $d->{ports_with_dynamic} : '-'),
      (defined $d->{updated}  ? $d->{updated} : 0),
      $picks_str;

  return Status->done(sprintf ' [%s] FortinetVlans done: %s', $device->ip, $summary);
});

true;
