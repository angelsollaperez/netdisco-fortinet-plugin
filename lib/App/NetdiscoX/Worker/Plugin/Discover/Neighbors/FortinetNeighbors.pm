package App::NetdiscoX::Worker::Plugin::Discover::Neighbors::FortinetNeighbors;

use Dancer ':syntax';
use App::Netdisco::Worker::Plugin;
use aliased 'App::Netdisco::Worker::Status';

use App::Netdisco::Transport::SNMP ();
use App::Netdisco::Util::Device qw/get_device is_discoverable/;
use App::Netdisco::Util::Permission 'acl_matches';
use App::Netdisco::JobQueue 'jq_insert';
use Dancer::Plugin::DBIC 'schema';
use List::Util 'pairs';
use NetAddr::IP::Lite ();
use NetAddr::MAC;
use Encode;
use Try::Tiny;

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
        return [];
    }

    # Fetch LLDP data
    my $lldp_url = "https://$device_ip/api/v2/monitor/switch/lldp-state";
    $response = $ua->get($lldp_url);

    if (!$response->is_success) {
        warn "Failed to fetch LLDP data: " . $response->status_line;
        return [];
    }

    my $data = decode_json($response->content);

    # Filter and transform results
    my @filtered_results;

    if (ref $data->{results} eq 'ARRAY') {
        foreach my $result (@{$data->{results}}) {
            next unless exists $result->{port} && $result->{port} && $result->{port_id};
            
            push @filtered_results, {
                local_port     => $result->{port},
                remote_port    => $result->{port_id},
                description    => $result->{port_description} // '',
                system_name    => $result->{system_name} // '',
                system_desc    => $result->{system_description} // '',
                management_ips => [
                    map { $_->{ip_address} } 
                    @{ $result->{management_ip_address} || [] }
                ]
            };
        }
    }

    return \@filtered_results;
}


register_worker({ phase => 'main', driver => 'snmp', priority=>1000 }, sub {
  my ($job, $workerconf) = @_;

  my $device = $job->device;
  return unless $device->vendor =~ /fortinet/i;
  return unless $device->in_storage;

  debug sprintf ' [%s] FortinetNeighbors plugin is running', $device->ip;

  if (acl_matches($device, 'skip_neighbors') or not setting('discover_neighbors')) {
      return Status->info(
        sprintf ' [%s] neigh - neighbor discovery is disabled on this device',
        $device->ip);
  }

  my $snmp = App::Netdisco::Transport::SNMP->reader_for($device)
    or return Status->defer("discover failed: could not SNMP connect to $device");

  my @to_discover = store_neighbors($device);
  my (%seen_id, %seen_ip) = ((), ());

  # only enqueue if device is not already discovered,
  # discover_* config permits the discovery
  foreach my $neighbor (@to_discover) {
      my ($ip, $remote_id) = @$neighbor;
      if ($seen_ip{ $ip }++) {
          debug sprintf
            ' queue - skip: IP %s is already queued from %s',
            $ip, $device->ip;
          next;
      }

      if ($remote_id and $seen_id{ $remote_id }++) {
          debug sprintf
            ' queue - skip: %s with ID [%s] already queued from %s',
            $ip, $remote_id, $device->ip;
          next;
      }

      my $newdev = get_device($ip);
      next if $newdev->in_storage;

      # risk of things going wrong...?
      # https://quickview.cloudapps.cisco.com/quickview/bug/CSCur12254

      jq_insert({
        device => $ip,
        action => 'discover',
        ($remote_id ? (device_key => $remote_id) : ()),
      });

      vars->{'queued'}->{$ip} = true;
      debug sprintf ' [%s] queue - queued %s for discovery (ID: [%s])',
        $device, $ip, ($remote_id || '');
  }

  return Status->done(sprintf ' [%s] FortinetNeighbors Done - processed %s neighbors',
       $device->ip, scalar @to_discover);
});


sub store_neighbors {
  my $device = shift;
  my @to_discover = ();

  debug sprintf ' [%s] neigh - Starting store_neighbors function', $device->ip;


  my $snmp = App::Netdisco::Transport::SNMP->reader_for($device)
    or return (); # already checked!

  # first allow any manually configured topology to be set
  # and do this before we cache the rows in vars->{'device_ports'}
  set_manual_topology($device);

  if (!defined $snmp->has_topo) {
      debug sprintf ' [%s] neigh - neighbor protocols are not enabled', $device->ip;
      return @to_discover;
  }

  my $interfaces = $snmp->interfaces;
  my $c_if       = $snmp->c_if;
  my $c_port     = $snmp->c_port;
  my $c_id       = $snmp->c_id;
  my $c_platform = $snmp->c_platform;
  my $c_cap      = $snmp->c_cap;

  # cache the device ports to save hitting the database for many single rows
  vars->{'device_ports'} =
    { map {($_->port => $_)} $device->ports->reset->all };
  my $device_ports = vars->{'device_ports'};

  # v4 and v6 neighbor tables
  my $c_ip = ($snmp->c_ip || {});
  my %c_ipv6 = %{ ($snmp->can('hasLLDP') and $snmp->hasLLDP)
    ? ($snmp->lldp_ipv6 || {}) : {} };
   
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

  if (ref $api_data_lldp eq 'ARRAY' && @$api_data_lldp){
    # Extract base SNMP number dynamically
    my ($base_snmp) = (keys %$c_ip)[0] =~ /^(\d+)\./;
    
    # 1. Handle multiple IP occurrences
    foreach my $ip (keys %{ { map { $_ => 1 } values %$c_ip } }) {
        my @indices = grep { $c_ip->{$_} eq $ip } keys %$c_ip;
        
        foreach my $api_entry (grep { 
            $_->{management_ips} && grep { $_ eq $ip } @{$_->{management_ips}} 
        } @$api_data_lldp) {
            
            my $port_num = $api_entry->{local_port} =~ s/^port//ir;
            my $subport = 1;
            
            while(exists $c_ip->{"$base_snmp.$port_num.$subport"}) {
                $subport++;
            }

            my $remote_port = $api_entry->{remote_port};
            # clean bracketed text like (mac) or (ifname)
            $remote_port =~ s/ \(.*?\)$//g;

            if($api_entry->{description} && $api_entry->{description} ne '' &&
               $api_entry->{remote_port} =~ /^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}( \(.*?\))?$/i) {
                $remote_port = $api_entry->{description};
            }
            
            unless(grep { $_ eq "$base_snmp.$port_num.$subport" } @indices) {
                $c_ip->{"$base_snmp.$port_num.$subport"} = $ip;
                $c_port->{"$base_snmp.$port_num.$subport"} = $remote_port;
                $c_if->{"$base_snmp.$port_num.$subport"} = $port_num;
            }
        }
    }
    
    # 2. Fix missing ports
    foreach my $neighbor (@$api_data_lldp) {
        next unless $neighbor->{management_ips};
        
        my $port_num = $neighbor->{local_port} =~ s/^port//ir;
        my $ip = $neighbor->{management_ips}[0] or next;
        
        unless(grep { $c_if->{$_} == $port_num } keys %$c_if) {
            my $subport = 1;
            while(exists $c_ip->{"$base_snmp.$port_num.$subport"}) {
                $subport++;
            }
            
            $c_ip->{"$base_snmp.$port_num.$subport"} = $ip;
            $c_port->{"$base_snmp.$port_num.$subport"} = $neighbor->{remote_port} =~ s/ \(.*?\)$//r;
            $c_if->{"$base_snmp.$port_num.$subport"} = $port_num;
        }
    }

    # clean incorrect mappings
    # 1. Track IP to SNMP indices
    my %ip_to_indices;
    foreach my $snmp_index (keys %$c_ip) {
        push @{$ip_to_indices{$c_ip->{$snmp_index}}}, $snmp_index;
    }
    
    # 2. Clean obsolete mappings
    foreach my $ip (keys %ip_to_indices) {
        foreach my $snmp_index (@{$ip_to_indices{$ip}}) {
            my $port = $c_if->{$snmp_index};
            
            my $valid = 0;
            foreach my $neighbor (@$api_data_lldp) {
                next unless $neighbor->{management_ips};
                
                my $api_port = $neighbor->{local_port};
                $api_port =~ s/^port//i;
                
                if(defined $api_port && defined $port && 
                   $api_port == $port && 
                   grep { $_ eq $ip } @{$neighbor->{management_ips}}) {
                    $valid = 1;
                    last;
                }
            }
            
            unless($valid) {
                delete $c_ip->{$snmp_index};
                delete $c_port->{$snmp_index};
                delete $c_if->{$snmp_index};
            }
        }
    }
  }

  
  # my %neighbor_info = (
  #     interfaces => $interfaces,
  #     c_if       => $c_if,
  #     c_port     => $c_port,
  #     c_id       => $c_id,
  #     c_platform => $c_platform,
  #     c_cap      => $c_cap,
  #     c_ip       => $c_ip,
  #     c_ipv6     => \%c_ipv6,
  # );

  # remove keys with undef values, as c_ip does
  delete @c_ipv6{ grep { not defined $c_ipv6{$_} } keys %c_ipv6 };

  # allow fallback from v6 to try v4
  my %success_with_index = ();

  NEIGHBOR: foreach my $pair (pairs %c_ipv6, %$c_ip) {
      my ($entry, $c_ip_entry) = (@$pair);
      next unless defined $entry and defined $c_ip_entry;

      debug sprintf ' [%s] neigh - Processing neighbor entry: %s', $device->ip, $entry;

      if (!defined $c_if->{$entry} or !defined $interfaces->{ $c_if->{$entry} }) {
          debug sprintf ' [%s] neigh - port for IID:%s not resolved, skipping',
            $device->ip, $entry;
          next NEIGHBOR;
      }

      # WRT #475 this is SAFE because we check against known ports below
      my $port = $interfaces->{ $c_if->{$entry} } or next NEIGHBOR;
      my $portrow = $device_ports->{$port};

      debug sprintf ' [%s] neigh - Mapped to port: %s', $device->ip, $port;

      if (!defined $portrow) {
          debug sprintf ' [%s] neigh - local port %s already skipped, ignoring',
            $device->ip, $port;
          next NEIGHBOR;
      }

      if (ref $c_ip_entry) {
          debug sprintf ' [%s] neigh - port %s has multiple neighbors - skipping',
            $device->ip, $port;
          next NEIGHBOR;
      }

      if ($portrow->manual_topo) {
          debug sprintf ' [%s] neigh - %s has manually defined topology',
            $device->ip, $port;
          next NEIGHBOR;
      }

      my $remote_ip   = $c_ip_entry;
      my $remote_port = undef;
      my $remote_type = Encode::decode('UTF-8', $c_platform->{$entry} || '');
      my $remote_id   = Encode::decode('UTF-8', $c_id->{$entry});
      my $remote_cap  = $c_cap->{$entry} || [];

      debug sprintf ' [%s] neigh - Neighbor info: IP: %s, Type: %s, ID: ', $device->ip, $remote_ip, $remote_type;

      next NEIGHBOR unless $remote_ip;
      my $r_netaddr = NetAddr::IP::Lite->new($remote_ip);

      if ($r_netaddr and ($r_netaddr->addr ne $remote_ip)) {
        debug sprintf ' [%s] neigh - IP on %s: using %s as canonical form of %s',
          $device->ip, $port, $r_netaddr->addr, $remote_ip;
        $remote_ip = $r_netaddr->addr;
      }

      if ($remote_ip and acl_matches($remote_ip, 'group:__LOCAL_ADDRESSES__')) {
          debug sprintf ' [%s] neigh - %s is a non-unique local address - skipping',
            $device->ip, $remote_ip;
          next NEIGHBOR;
      }

      # a bunch of heuristics to search known devices if we do not have a
      # useable remote IP...

      if ((! $r_netaddr) or ($remote_ip eq '0.0.0.0') or
        acl_matches($remote_ip, 'group:__LOOPBACK_ADDRESSES__')) {

          if ($remote_id) {
              my $devices = schema('netdisco')->resultset('Device');

              debug sprintf
                ' [%s] neigh - bad address %s on port %s, searching for %s instead',
                $device->ip, $remote_ip, $port, $remote_id;
              my $neigh_rs = $devices->search_rs({name => $remote_id});
              my $neigh = ($neigh_rs->count == 1 ? $neigh_rs->first : undef);

              if (!defined $neigh and $neigh_rs->count) {
                  debug sprintf ' [%s] neigh - multiple devices claim to be %s (port %s) - skipping',
                    $device->ip, $remote_id, $port;
                  next NEIGHBOR;
              }

              if (!defined $neigh) {
                  my $mac = NetAddr::MAC->new(mac => ($remote_id || ''));
                  if ($mac and not $mac->errstr) {
                      $neigh = $devices->single({mac => $mac->as_ieee});
                  }
              }

              # some HP switches send 127.0.0.1 as remote_ip if no ip address
              # on default vlan for HP switches remote_ip looks like
              # "myswitchname(012345-012345)"
              if (!defined $neigh) {
                  (my $tmpid = $remote_id) =~ s/.*\(([0-9a-f]{6})-([0-9a-f]{6})\).*/$1$2/;
                  my $mac = NetAddr::MAC->new(mac => ($tmpid || ''));
                  if ($mac and not $mac->errstr) {
                      debug sprintf
                        ' [%s] neigh - trying to find neighbor %s by MAC %s',
                        $device->ip, $remote_id, $mac->as_ieee;
                      $neigh = $devices->single({mac => $mac->as_ieee});
                  }
              }

              if (!defined $neigh) {
                  (my $shortid = $remote_id) =~ s/\..*//;
                  $neigh = $devices->single({name => { -ilike => "${shortid}%" }});
              }

              if ($neigh) {
                  $remote_ip = $neigh->ip;
                  debug sprintf ' [%s] neigh - found %s with IP %s',
                    $device->ip, $remote_id, $remote_ip;
              }
              else {
                  debug sprintf ' [%s] neigh - could not find %s, skipping',
                    $device->ip, $remote_id;
                  next NEIGHBOR;
              }
          }
          else {
              debug sprintf ' [%s] neigh - skipping unuseable address %s on port %s',
                $device->ip, $remote_ip, $port;
              next NEIGHBOR;
          }
      }

      if (++$success_with_index{$entry} > 1) {
          debug sprintf ' [%s] neigh - port for IID:%s already got a neighbor, skipping',
            $device->ip, $entry;
          next NEIGHBOR;
      }

      # what we came here to do.... discover the neighbor
      debug sprintf ' [%s] neigh - %s with ID [%s] on %s',
        $device->ip, $remote_ip, ($remote_id || ''), $port;

      if (is_discoverable($remote_ip, $remote_type, $remote_cap)) {
          push @to_discover, [$remote_ip, $remote_id];
      }
      else {
          debug sprintf
            ' [%s] neigh - skip: %s of type [%s] excluded by discover_* config',
            $device->ip, $remote_ip, ($remote_type || '');
      }

      $remote_port = $c_port->{$entry};
      if (defined $remote_port) {
          # clean weird characters
          $remote_port =~ s/[^\d\s\/\.,"()\w:-]+//gi;
      }
      else {
          debug sprintf ' [%s] neigh - no remote port found for port %s at %s',
            $device->ip, $port, $remote_ip;
      }

      $portrow = $portrow->update({
          remote_ip   => $remote_ip,
          remote_port => $remote_port,
          remote_type => $remote_type,
          remote_id   => $remote_id,
          is_uplink   => \"true",
          manual_topo => \"false",
      })->discard_changes();

      # update master of our aggregate to be a neighbor of
      # the master on our peer device (a lot of iffs to get there...).
      # & cannot use ->neighbor prefetch because this is the port insert!
      if (defined $portrow->slave_of) {

          my $peer_device = get_device($remote_ip);
          my $master = schema('netdisco')->resultset('DevicePort')->single({
            ip => $device->ip,
            port => $portrow->slave_of
          });

          if ($peer_device and $peer_device->in_storage and $master
              and not ($portrow->is_master or defined $master->slave_of)) {

              my $peer_port = schema('netdisco')->resultset('DevicePort')->single({
                ip   => $peer_device->ip,
                port => $portrow->remote_port,
              });

              $master->update({
                  remote_ip => ($peer_device->ip || $remote_ip),
                  remote_port => ($peer_port ? $peer_port->slave_of : undef ),
                  is_uplink => \"true",
                  is_master => \"true",
                  manual_topo => \"false",
              });
          }
      
      debug sprintf ' [%s] neigh - Successfully processed neighbor on port %s', $device->ip, $port;
      }
  }

  return @to_discover;
}

# take data from the topology table and update remote_ip and remote_port
# in the devices table. only use root_ips and skip any bad topo entries.
sub set_manual_topology {
  my $device = shift;
  my $snmp = App::Netdisco::Transport::SNMP->reader_for($device) or return;

  schema('netdisco')->txn_do(sub {
    # clear manual topology flags
    schema('netdisco')->resultset('DevicePort')
      ->search({ip => $device->ip})->update({manual_topo => \'false'});

    # clear outdated manual topology links
    my $old_links = schema('netdisco')->resultset('Topology')->search({
      -or => [
        { dev1 => $device->ip,
          port1 => { '-not_in' => $device->ports->get_column('port')->as_query } },
        { dev2 => $device->ip,
          port2 => { '-not_in' => $device->ports->get_column('port')->as_query } },
      ],
    })->delete;
    debug sprintf ' [%s] neigh - removed %d outdated manual topology links',
      $device->ip, $old_links;

    my $topo_links = schema('netdisco')->resultset('Topology')
      ->search({-or => [dev1 => $device->ip, dev2 => $device->ip]});
    debug sprintf ' [%s] neigh - setting manual topology links', $device->ip;

    while (my $link = $topo_links->next) {
        # could fail for broken topo, but we ignore to try the rest
        try {
            schema('netdisco')->txn_do(sub {
              # only work on root_ips
              my $left  = get_device($link->dev1);
              my $right = get_device($link->dev2);

              # skip bad entries
              return unless ($left->in_storage and $right->in_storage);

              $left->ports
                ->single({port => $link->port1})
                ->update({
                  remote_ip => $right->ip,
                  remote_port => $link->port2,
                  remote_type => undef,
                  remote_id   => undef,
                  is_uplink   => \"true",
                  manual_topo => \"true",
                });

              $right->ports
                ->single({port => $link->port2})
                ->update({
                  remote_ip => $left->ip,
                  remote_port => $link->port1,
                  remote_type => undef,
                  remote_id   => undef,
                  is_uplink   => \"true",
                  manual_topo => \"true",
                });
            });
        };
    }
  });
}

true;
