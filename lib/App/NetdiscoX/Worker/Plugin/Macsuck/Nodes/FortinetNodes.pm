package App::NetdiscoX::Worker::Plugin::Macsuck::Nodes::FortinetNodes;

use Dancer ':syntax';
use App::Netdisco::Worker::Plugin;
use aliased 'App::Netdisco::Worker::Status';

use App::Netdisco::Transport::SSH ();
use App::Netdisco::Transport::SNMP ();
use App::Netdisco::Util::Permission 'acl_matches';
use App::Netdisco::Util::PortMAC 'get_port_macs';
use App::Netdisco::Util::Device 'match_to_setting';
use App::Netdisco::Util::Node 'check_mac';
use App::Netdisco::Util::SNMP 'snmp_comm_reindex';
use App::Netdisco::Util::Web 'sort_port';

use Dancer::Plugin::DBIC 'schema';
use Time::HiRes 'gettimeofday';
use File::Slurper 'read_text';
use Scope::Guard 'guard';
use Regexp::Common 'net';
use NetAddr::MAC ();
use List::MoreUtils ();
use LWP::UserAgent;
use JSON qw(decode_json);

# -------------------------------------------------------------
# Custom definitions for VLAN processing over SNMP:Info
# -------------------------------------------------------------

use strict;
use warnings;
use Exporter;
use SNMP::Info;
@SNMP::Info::Bridge::ISA       = qw/SNMP::Info Exporter/;
@SNMP::Info::Bridge::EXPORT_OK = qw//;


my %FUNCS = (
    # Bridge Port Table: Dot1dBasePortEntry
    'bp_index' => 'dot1dBasePortIfIndex',

    # Q-BRIDGE-MIB : dot1qPortVlanTable
    'qb_i_vlan' => 'dot1qPvid',

    # Q-BRIDGE-MIB : dot1qVlanCurrentTable
    'qb_cv_egress'   => 'dot1qVlanCurrentEgressPorts',
    'qb_cv_untagged' => 'dot1qVlanCurrentUntaggedPorts',

    # Q-BRIDGE-MIB : dot1qVlanStaticTable
    'qb_v_egress'   => 'dot1qVlanStaticEgressPorts',
    'qb_v_untagged' => 'dot1qVlanStaticUntaggedPorts',
);

my %MUNGE = (
    %SNMP::Info::MUNGE,
    'qb_cv_egress'   => \&SNMP::Info::munge_port_list,
    'qb_cv_untagged' => \&SNMP::Info::munge_port_list,
    'qb_v_egress'    => \&SNMP::Info::munge_port_list,
    'qb_v_untagged'  => \&SNMP::Info::munge_port_list,
);

# -------------------------------------------------------------
# Custom functions - override defaults
# -------------------------------------------------------------

sub i_vlan_plugin {
    my $bridge  = shift;
    my $partial = shift;

    debug sprintf ' [] i_vlan_plugin: Starting';

    my $i_pvid = $bridge->qb_i_vlan($partial) || {};
    #debug sprintf ' [] i_vlan_plugin: qb_i_vlan result: %s', to_json($i_pvid);

    my $i_vlan = {};

    foreach my $port ( keys %$i_pvid ) {
        my $vlan = $i_pvid->{$port};
        $i_vlan->{$port} = $vlan;
    }

    debug sprintf ' [] i_vlan_plugin: Final result: %s', to_json($i_vlan);
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
    my $v_name = shift;

    #debug sprintf ' [] i_vlan_membership_plugin: Starting';
    my $v_ports = $bridge->qb_cv_egress() || $bridge->qb_v_egress();
    #debug sprintf ' [] i_vlan_membership_plugin: v_ports: %s', to_json($v_ports);

    my $result = _vlan_hoa_plugin($bridge, $v_ports, $partial);
    my %mapped_result;
    foreach my $port (keys %$result) {
        $mapped_result{$port} = [
            map { map_vlan_id_to_name($v_name, $_) } @{$result->{$port}}
        ];
    }
    #debug sprintf ' [] i_vlan_membership_plugin: Final result: %s', to_json(\%mapped_result);
    return \%mapped_result;
}

sub _vlan_hoa_plugin {
    my $bridge = shift;
    my ( $v_ports, $partial ) = @_;

    my $vlan_hoa = {};
    foreach my $idx ( keys %$v_ports ) {
        next unless ( defined $v_ports->{$idx} );
        my $portlist = $v_ports->{$idx};
        my $ret      = [];
        my $vlan;

        ($vlan = $idx) =~ s/^(\d+\.)*//g;
        for ( my $i = 0; $i <= $#$portlist; $i++ ) {
            if ( @$portlist[$i] ) {
                my $port_number = $i + 1;
                push( @{ $vlan_hoa->{$port_number} }, $vlan );
            }
        }
    }

    return $vlan_hoa;
}

sub fetch_dynamic_vlan_api {
    my ($device_ip, $user, $password, $token) = @_;
    return unless $device_ip && (($user && $password) || $token);

    my $ua = LWP::UserAgent->new(
        cookie_jar => {},
        ssl_opts   => { SSL_verify_mode => 0, verify_hostname => 0 },
    );
    $ua->timeout(10);

    my $base_url = _fortinet_api_base_url($device_ip);

    if ($token) {
        $ua->default_header(Authorization => "Bearer $token");
    }
    else {
        my $login = $ua->post("$base_url/logincheck", {
            username  => $user,
            secretkey => $password,
        });

        unless ($login->is_success) {
            debug sprintf ' [FortinetNodes API] dynamic VLAN login to %s failed: %s',
                $device_ip, $login->status_line;
            return;
        }
    }

    my $response = $ua->get(
        "$base_url/api/v2/monitor/switch-controller/managed-switch/status?mkey=all"
    );

    unless ($response->is_success) {
        debug sprintf ' [FortinetNodes API] dynamic VLAN GET from %s failed: %s',
            $device_ip, $response->status_line;
        return;
    }

    my $data = eval { decode_json($response->content) };
    if ($@) {
        debug sprintf ' [FortinetNodes API] dynamic VLAN JSON decode failed: %s', $@;
        return;
    }

    return $data if ref $data eq 'HASH';
    return;
}

sub _first_defined {
    my ($hash, @keys) = @_;
    return unless ref $hash eq 'HASH';

    foreach my $key (@keys) {
        next unless exists $hash->{$key};
        next unless defined $hash->{$key};
        next if !ref $hash->{$key} && $hash->{$key} eq '';
        return $hash->{$key};
    }

    return;
}

sub _fortinet_api_base_url {
    my $host = shift;
    return unless defined $host && length "$host";

    $host =~ s{/$}{};
    return $host if $host =~ m{^https?://}i;
    return "https://$host";
}

sub _vlan_number {
    my $value = shift;
    return unless defined $value;

    if (ref $value eq 'HASH') {
        $value = _first_defined($value, qw(id vlan vlanid name));
        return unless defined $value;
    }

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

sub _switch_values {
    my $switch = shift;
    return () unless ref $switch eq 'HASH';

    my @values;
    foreach my $key (qw(_api_switch_key serial serial_number switch_id id mkey name hostname ip ip_addr ip_address management_ip connecting_from)) {
        next unless exists $switch->{$key};
        my $value = $switch->{$key};
        if (ref $value eq 'ARRAY') {
            push @values, grep { defined $_ && length "$_" } @$value;
        }
        elsif (!ref $value) {
            push @values, $value if defined $value && length "$value";
        }
    }

    return @values;
}

sub _switch_matches_device {
    my ($switch, $device) = @_;

    my @device_values = grep { defined $_ && length "$_" }
        map { _device_value($device, $_) } qw(ip name dns serial mac);
    my %device_identity = map { $_ => 1 }
        grep { defined $_ } map { _normalize_identity($_) } @device_values;

    foreach my $switch_value (_switch_values($switch)) {
        my $identity = _normalize_identity($switch_value);
        return 1 if $identity && $device_identity{$identity};
    }

    return 0;
}

sub _api_switches {
    my $api_data = shift;
    return () unless ref $api_data eq 'HASH';

    my $results = $api_data->{results};
    return grep { ref $_ eq 'HASH' } @$results if ref $results eq 'ARRAY';
    return map {{
        _api_switch_key => $_,
        %{ $results->{$_} },
    }} grep { ref $results->{$_} eq 'HASH' } keys %$results if ref $results eq 'HASH';

    return ();
}

sub _matching_api_switches {
    my ($api_data, $device) = @_;

    my @switches = _api_switches($api_data);
    return @switches if @switches == 1;

    return grep { _switch_matches_device($_, $device) } @switches;
}

sub _switch_ports {
    my $switch = shift;
    return () unless ref $switch eq 'HASH';

    foreach my $key (qw(ports port_list switch_ports)) {
        next unless exists $switch->{$key};
        my $ports = $switch->{$key};
        return grep { ref $_ eq 'HASH' } @$ports if ref $ports eq 'ARRAY';
        return map {{
            _api_port_key => $_,
            %{ $ports->{$_} },
        }} grep { ref $ports->{$_} eq 'HASH' } keys %$ports if ref $ports eq 'HASH';
    }

    return ();
}

sub _api_port_name {
    my $port_info = shift;
    return _first_defined($port_info, qw(_api_port_key port_name port ifname interface name));
}

sub _dynamic_vlan_number {
    my $value = shift;

    if (ref $value eq 'HASH') {
        foreach my $key (keys %$value) {
            next unless $key =~ /^(?:dynamic[-_]?vlan|dyn[-_]?vlan|assigned[-_]?vlan|auth[-_]?vlan|nac[-_]?vlan)$/i;
            my $vlan = _vlan_number($value->{$key});
            return $vlan if $vlan;
        }

        foreach my $key (keys %$value) {
            my $vlan = _dynamic_vlan_number($value->{$key});
            return $vlan if $vlan;
        }
    }
    elsif (ref $value eq 'ARRAY') {
        foreach my $item (@$value) {
            my $vlan = _dynamic_vlan_number($item);
            return $vlan if $vlan;
        }
    }

    return;
}

sub _build_port_lookup {
    my $device_ports = shift || {};
    my %lookup;

    foreach my $port (keys %$device_ports) {
        $lookup{$port} ||= $port;
        $lookup{lc $port} ||= $port;

        my $normalized = _normalize_port_key($port);
        $lookup{$normalized} ||= $port if $normalized;

        if ($port =~ /^port(\d+)$/i) {
            $lookup{$1} ||= $port;
        }
    }

    return \%lookup;
}

sub _fortinet_api_credentials {
    my $device = shift;

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

    if ($api_host && $fortinet_auth->{port} && $api_host !~ m{:\d+(?:/)?$} && $api_host !~ m{^https?://[^/]+:\d+}i) {
        $api_host .= ':' . $fortinet_auth->{port};
    }

    return unless $api_host;
    return ($api_host, $fortinet_auth->{username}, $fortinet_auth->{password},
        $fortinet_auth->{token} || $fortinet_auth->{api_token});
}

sub _resolve_device_port {
    my ($port_lookup, $api_port) = @_;
    return unless defined $api_port;

    return $port_lookup->{$api_port}
        || $port_lookup->{lc "$api_port"}
        || $port_lookup->{_normalize_port_key($api_port)};
}

sub _dynamic_vlan_map_from_port_vlans {
    my ($device, $device_ports) = @_;
    my %port_vlans;

    my @rows = eval {
        schema('netdisco')->resultset('DevicePortVlan')->search({
            ip => $device->ip,
        })->all;
    };
    if ($@) {
        debug sprintf ' [%s] macsuck dynamic VLAN: direct device_port_vlan read failed: %s',
            $device->ip, $@;
        @rows = ();
    }

    @rows = eval { $device->port_vlans->all } unless @rows;
    if ($@) {
        debug sprintf ' [%s] macsuck dynamic VLAN: could not read device_port_vlan rows: %s',
            $device->ip, $@;
        return;
    }

    foreach my $row (@rows) {
        my $port = eval { $row->port };
        next unless defined $port && length "$port";
        next unless $device_ports->{$port};

        my $vlan = _vlan_number(eval { $row->vlan });
        next unless $vlan;

        push @{ $port_vlans{$port} }, $vlan;
    }

    my %dynamic_vlan_map;
    foreach my $port (keys %port_vlans) {
        my @vlans = List::MoreUtils::uniq(@{ $port_vlans{$port} });

        my $dp = $device_ports->{$port};
        next unless $dp;

        my $native = _vlan_number(eval { $dp->vlan });
        next unless defined $native;

        my @dynamic_vlans = grep { $_ != $native } @vlans;
        next unless @dynamic_vlans == 1;

        $dynamic_vlan_map{$port} = $dynamic_vlans[0];
        debug sprintf ' [%s] macsuck dynamic VLAN from Fortinet membership fallback: port=%s native=%s membership=%s dynamic=%s',
            $device->ip, $port, $native, join(',', @vlans), $dynamic_vlans[0];
    }

    return %dynamic_vlan_map;
}
# -------------------------------------------------------------
# END Custom functions
# -------------------------------------------------------------


register_worker({ phase => 'early',
  title => 'prepare common data', 
  priority => 1000 }, sub {

  my ($job, $workerconf) = @_;
  my $device = $job->device;
  return unless $device->vendor =~ /fortinet/i;

  vars->{'timestamp'} = ($job->is_offline and $job->entered)
    ? (schema('netdisco')->storage->dbh->quote($job->entered) .'::timestamp')
    : 'to_timestamp('. (join '.', gettimeofday) .')::timestamp';

  # initialise the cache
  vars->{'fwtable'} = {};

  # cache the device ports to save hitting the database for many single rows
  vars->{'device_ports'} = {map {($_->port => $_)}
                          $device->ports(undef, {prefetch => ['properties',
                                                              {neighbor_alias => 'device'}]})->all};
});

register_worker({ phase => 'main', 
    driver => 'direct',
    title => 'gather macs from file', 
    priority => 1000 }, sub {

  my ($job, $workerconf) = @_;
  my $device = $job->device;
  return unless $device->vendor =~ /fortinet/i;

  return Status->info('skip: fwtable data supplied by other source')
    unless $job->is_offline;

  # load cache from file or copy from job param
  my $data = $job->extra;

  if ($job->port) {
    return $job->cancel(sprintf 'could not open data source "%s"', $job->port)
      unless -f $job->port;

    $data = read_text($job->port)
      or return $job->cancel(sprintf 'problem reading from file "%s"', $job->port);
  }

  my @fwtable = (length $data ? @{ from_json($data) } : ());

  return $job->cancel('data provided but 0 fwd entries found')
    unless scalar @fwtable;

  debug sprintf ' [%s] macsuck - %s forwarding table entries provided',
    $device->ip, scalar @fwtable;

  # rebuild fwtable in format for filtering more easily
  foreach my $node (@fwtable) {
      my $mac = NetAddr::MAC->new(mac => ($node->{'mac'} || ''));
      next unless $node->{'port'} and $mac;
      next if (($mac->as_ieee eq '00:00:00:00:00:00') or ($mac->as_ieee !~ m{^$RE{net}{MAC}$}i));

      vars->{'fwtable'}->{ $node->{'vlan'} || 0 }
                       ->{ $node->{'port'} }
                       ->{ $mac->as_ieee } += 1;
  }

  return Status->done("Received MAC addresses for $device");
});

register_worker({ phase => 'main', 
    driver => 'cli',
    title => 'gather macs from CLI', 
    priority => 1000}, sub {

  my ($job, $workerconf) = @_;
  my $device = $job->device;
  return unless $device->vendor =~ /fortinet/i;

  my $cli = App::Netdisco::Transport::SSH->session_for($device)
    or return Status->defer("macsuck failed: could not SSH connect to $device");

  # Retrieve data through SSH connection
  my $macs = $cli->macsuck;

  my $nodecount = 0;
  foreach my $vlan (keys %{ $macs }) {
    foreach my $port (keys %{ $macs->{$vlan} }) {
      $nodecount += scalar keys %{ $macs->{$vlan}->{$port} };
    }
  }

  return $job->cancel('data provided but 0 fwd entries found')
    unless $nodecount;

  debug sprintf ' [%s] macsuck - %s forwarding table entries provided',
    $device->ip, $nodecount;

  # get forwarding table and populate fwtable
  vars->{'fwtable'} = $macs;

  return Status->done("Gathered MAC addresses for $device");
});

register_worker({ phase => 'main', 
    driver => 'snmp',
    title => 'gather macs from snmp', 
    priority => 1000}, sub {

  my ($job, $workerconf) = @_;
  my $device = $job->device;
  return unless $device->vendor =~ /fortinet/i;

  my $snmp = App::Netdisco::Transport::SNMP->reader_for($device)
    or return Status->defer("macsuck failed: could not SNMP connect to $device");

  # get forwarding table data via basic snmp connection
  my $interfaces = $snmp->interfaces || {};
  vars->{'fwtable'} = walk_fwtable($snmp, $device, $interfaces);

  # ...then per-vlan if supported
  # this will duplicate call sanity_vlans (same as store) but helps efficiency
  my @vlan_list = get_vlan_list($snmp, $device);
  {
    my $guard = guard { snmp_comm_reindex($snmp, $device, 0) };
    foreach my $vlan (@vlan_list) {
      snmp_comm_reindex($snmp, $device, $vlan);
      my $pv_fwtable =
        walk_fwtable($snmp, $device, $interfaces, $vlan);
      vars->{'fwtable'} = {%{ vars->{'fwtable'} }, %$pv_fwtable};
    }
  }

  return Status->done("Gathered MAC addresses for $device");
});


register_worker({ phase => 'store',
  title => 'save macs to database', 
  priority => 1000}, sub {

  my ($job, $workerconf) = @_;
  my $device = $job->device;
  return unless $device->vendor =~ /fortinet/i;

  # remove macs on forbidden vlans
  my @vlans = (0, sanity_vlans($device, vars->{'fwtable'}, {}, {}));
  foreach my $vlan (keys %{ vars->{'fwtable'} }) {
      delete vars->{'fwtable'}->{$vlan}
        unless scalar grep {$_ eq $vlan} @vlans;
  }


  # sanity filter the MAC addresses from the device
  vars->{'fwtable'} = sanity_macs( $device, vars->{'fwtable'}, vars->{'device_ports'} );

  # Get the dynamic VLAN for each port from Discover data or the FortiGate API.
  my %dynamic_vlan_map = _dynamic_vlan_map_from_port_vlans(
      $device, vars->{'device_ports'}
  );
  eval {
      my ($api_host, $api_user, $api_pass, $api_token) = _fortinet_api_credentials($device);
      if ($api_host && (($api_user && $api_pass) || $api_token)) {
          my $api_data = fetch_dynamic_vlan_api($api_host, $api_user, $api_pass, $api_token);
          if ($api_data) {
              my @switches = _matching_api_switches($api_data, $device);
              my $port_lookup = _build_port_lookup(vars->{'device_ports'});
              foreach my $switch (@switches) {
                  foreach my $port_info (_switch_ports($switch)) {
                      my $api_port = _api_port_name($port_info);
                      my $port = _resolve_device_port($port_lookup, $api_port);
                      next unless $port;
                      my $dyn = _dynamic_vlan_number($port_info);
                      next unless $dyn;
                      my $dp = vars->{'device_ports'}->{$port};
                      next unless $dp;
                      my $native = _vlan_number(eval { $dp->vlan });
                      next unless defined $native && $dyn != $native;
                      $dynamic_vlan_map{$port} = $dyn;
                      debug sprintf ' [%s] macsuck dynamic VLAN: port=%s native=%s dynamic=%s',
                          $device->ip, $port, $native, $dyn;
                  }
              }
          }
      }
      1;
  } or do {
      my $error = $@;
      debug sprintf ' [%s] macsuck dynamic VLAN lookup failed (non-fatal): %s',
        $device->ip, $error if $error;
  };
  
  
  # reverse sort allows vlan 0 entries to be included only as fallback
  my $node_count = 0;
  foreach my $vlan (reverse sort keys %{ vars->{'fwtable'} }) {
      foreach my $port (keys %{ vars->{'fwtable'}->{$vlan} }) {
          my $vlabel = ($vlan ? $vlan : 'unknown');
          debug sprintf ' [%s] macsuck - port %s vlan %s : %s nodes',
            $device->ip, $port, $vlabel, scalar keys %{ vars->{'fwtable'}->{$vlan}->{$port} };

          foreach my $mac (keys %{ vars->{'fwtable'}->{$vlan}->{$port} }) {

              # remove vlan 0 entry for this MAC addr
              delete vars->{'fwtable'}->{0}->{$_}->{$mac}
                for keys %{ vars->{'fwtable'}->{0} };

              my $effective_vlan = $dynamic_vlan_map{$port} // $vlan;
              debug sprintf ' [%s] macsuck dynamic VLAN override: port=%s learned=%s stored=%s',
                $device->ip, $port, $vlan, $effective_vlan
                if defined $dynamic_vlan_map{$port} && $effective_vlan != $vlan;
              store_node($device->ip, $effective_vlan, $port, $mac, vars->{'timestamp'});
              ++$node_count;
          }
      }
  }

  debug sprintf ' [%s] macsuck - stored %s forwarding table entries',
    $device->ip, $node_count;

  # a use for $now ... need to archive disappeared nodes
  my $now = vars->{'timestamp'};
  my $archived = 0;

  if (setting('node_freshness')) {
    $archived = schema('netdisco')->resultset('Node')->search({
      switch => $device->ip,
      time_last => \[ "< ($now - ?::interval)",
        setting('node_freshness') .' minutes' ],
    })->update({ active => \'false' });
  }

  debug sprintf ' [%s] macsuck - removed %d fwd table entries to archive',
    $device->ip, $archived;

  $device->update({last_macsuck => \$now});

  my $status = $job->best_status;
  return Status->$status("Ended macsuck for $device");
});


sub store_node {
  my ($ip, $vlan, $port, $mac, $now) = @_;
  $now ||= 'LOCALTIMESTAMP';
  $vlan ||= 0;

  # ideally we just store the first 36 bits of the mac in the oui field
  # and then no need for this query. haven't yet worked out the SQL for that.
  my $oui = schema('netdisco')->resultset('Manufacturer')
    ->search({ range => { '@>' =>
      \[q{('x' || lpad( translate( ? ::text, ':', ''), 16, '0')) ::bit(64) ::bigint}, $mac]} },
      { rows => 1, columns => 'base' })->first;

  schema('netdisco')->txn_do(sub {
    my $nodes = schema('netdisco')->resultset('Node');

    my $old = $nodes->search(
        { mac   => $mac,
          # where vlan is unknown, need to archive on all other vlans
          ($vlan ? (vlan => $vlan) : ()),
          -bool => 'active',
          -not  => {
                    switch => $ip,
                    port   => $port,
                  },
        })->update( { active => \'false' } );

    # If FortiGate API supplied a real VLAN, retire stale vlan=0/native
    # rows for the same MAC on this exact port.
    if ($vlan) {
      $nodes->search(
        {
          mac    => $mac,
          switch => $ip,
          port   => $port,
          -bool  => 'active',
          vlan   => { '!=' => $vlan },
        }
      )->update({ active => \'false' });
    }

    # new data
    my $row = $nodes->update_or_new(
      {
        switch => $ip,
        port => $port,
        vlan => $vlan,
        mac => $mac,
        active => \'true',
        oui => ($oui ? $oui->base : undef),
        time_last => \$now,
        (($old != 0) ? (time_recent => \$now) : ()),
      },
      {
        key => 'primary',
        for => 'update',
      }
    );

    if (! $row->in_storage) {
        $row->set_column(time_first => \$now);
        $row->insert;
    }
  });
}

# return a list of vlan numbers which are OK to macsuck on this device
sub get_vlan_list {
  my ($snmp, $device) = @_;
  return () unless $snmp->cisco_comm_indexing;

  my (%vlans, %vlan_names, %vlan_states);
  my $i_vlan = $snmp->i_vlan_plugin || {};
  my $trunks = $snmp->i_vlan_membership_plugin || {};
  my $i_type = $snmp->i_type || {};


  # get list of vlans in use
  while (my ($idx, $vlan) = each %$i_vlan) {
      # hack: if vlan id comes as 1.142 instead of 142
      $vlan =~ s/^\d+\.//;
      
      if (exists $i_type->{$idx} and $i_type->{$idx} eq 'propVirtual') {
        $vlans{$vlan} ||= 0;
      }
      else {
        ++$vlans{$vlan};
      }
      foreach my $t_vlan (@{$trunks->{$idx}}) {
        ++$vlans{$t_vlan};
      }
  }

  unless (scalar keys %vlans) {
      debug sprintf ' [%s] macsuck - no VLANs found.', $device->ip;
      return ();
  }

  my $v_name = $snmp->v_name || {};
   
  # -------------------------------------------------------------
  # Remapping the VLANS for Forti
  # -------------------------------------------------------------
  my %copy = %$v_name;
  my $v_index = \%copy;

  foreach my $key (keys %$v_name) {
    $v_index->{$key} =~ s/vlan//;  # Remove "vlan"
    $v_index->{$key} = $v_index->{$key} =~ /(\d+)/ ? $1 : '0';  # Extract number or set to '0'
  }
  
  # get vlan names (required for config which filters by name)
  while (my ($idx, $name) = each %$v_name) {
      # hack: if vlan id comes as 1.142 instead of 142
      (my $vlan = $idx) =~ s/^\d+\.//;

      # just in case i_vlan is different to v_name set
      # capture the VLAN, but it's not in use on a port
      $vlans{$vlan} ||= 0;

      $vlan_names{$vlan} = $name;
  }

  debug sprintf ' [%s] macsuck - VLANs: %s', $device->ip,
    (join ',', sort grep {$_} keys %vlans);

  my $v_state = $snmp->v_state || {};

  # get vlan states (required for ignoring suspended vlans)
  while (my ($idx, $state) = each %$v_state) {
      # hack: if vlan id comes as 1.142 instead of 142
      (my $vlan = $idx) =~ s/^\d+\.//;

      # just in case i_vlan is different to v_name set
      # capture the VLAN, but it's not in use on a port
      $vlans{$vlan} ||= 0;

      $vlan_states{$vlan} = $state;
  }

  return sanity_vlans($device, \%vlans, \%vlan_names, \%vlan_states);
}

sub sanity_vlans {
  my ($device, $vlans, $vlan_names, $vlan_states) = @_;

  my @ok_vlans = ();
  foreach my $vlan (sort keys %$vlans) {
      my $name = $vlan_names->{$vlan} || '(unnamed)';
      my $state = $vlan_states->{$vlan} || '(unknown)';

      if (ref [] eq ref setting('macsuck_no_vlan')) {
          my $ignore = setting('macsuck_no_vlan');

          if ((scalar grep {$_ eq $vlan} @$ignore) or
              (scalar grep {$_ eq $name} @$ignore)) {

              debug sprintf
                ' [%s] macsuck VLAN %s - skipped by macsuck_no_vlan config',
                $device->ip, $vlan;
              next;
          }
      }

      if (ref [] eq ref setting('macsuck_no_devicevlan')) {
          my $ignore = setting('macsuck_no_devicevlan');
          my $ip = $device->ip;

          if ((scalar grep {$_ eq "$ip:$vlan"} @$ignore) or
              (scalar grep {$_ eq "$ip:$name"} @$ignore)) {

              debug sprintf
                ' [%s] macsuck VLAN %s - skipped by macsuck_no_devicevlan config',
                $device->ip, $vlan;
              next;
          }
      }

      if (setting('macsuck_no_unnamed') and $name eq '(unnamed)') {
          debug sprintf
            ' [%s] macsuck VLAN %s - skipped by macsuck_no_unnamed config',
            $device->ip, $vlan;
          next;
      }

      if ($vlan > 4094) {
          debug sprintf ' [%s] macsuck - invalid VLAN number %s',
            $device->ip, $vlan;
          next;
      }
      next if $vlan == 0; # quietly skip

      # check in use by a port on this device
      if (not $vlans->{$vlan} and not setting('macsuck_all_vlans')) {
          debug sprintf
            ' [%s] macsuck VLAN %s/%s - not in use by any port - skipping.',
            $device->ip, $vlan, $name;
          next;
      }

      # check if vlan is in state 'suspended'
      if ($state eq 'suspended') {
          debug sprintf
            ' [%s] macsuck VLAN %s - VLAN is suspended - skipping.',
            $device->ip, $vlan;
          next;
      }

      push @ok_vlans, $vlan;
  }

  return @ok_vlans;
}

# walks the forwarding table (BRIDGE-MIB) for the device and returns a
# table of node entries.
sub walk_fwtable {
  my ($snmp, $device, $interfaces, $comm_vlan) = @_;
  my $cache = {};

  my $fw_mac   = $snmp->fw_mac || {};
  my $fw_port  = $snmp->fw_port || {};
  my $fw_vlan  = ($snmp->can('cisco_comm_indexing') and $snmp->cisco_comm_indexing()) 
    ? {} : $snmp->qb_fw_vlan;
  my $bp_index = $snmp->bp_index || {};

  MAC: while (my ($idx, $mac) = each %$fw_mac) {
      # Use fw_port directly as the port index
      my $port_index = $fw_port->{$idx};

      unless (defined $port_index) {
          debug sprintf(
              ' [%s] macsuck %s - %s has no fw_port mapping - skipping.',
              $device->ip, $mac, $idx
          );
          next MAC;
      }

      # Map port index directly to port name using interfaces hash
      my $port_name = $interfaces->{$port_index};
      my $vlan = $fw_vlan->{$idx} || $comm_vlan || '0';

      unless (defined $port_name) {
          debug sprintf(
              ' [%s] macsuck %s - port index %s has no port name mapping - skipping.',
              $device->ip, $mac, $port_index
          );
          next MAC;
      }

      # Increment cache for VLAN, port name, and MAC address
      ++$cache->{$vlan}->{$port_name}->{$mac};
      
  }

  return $cache;
}

sub sanity_macs {
  my ($device, $cache, $device_ports) = @_;

  # note any of the MACs which are actually device or device_port MACs
  # used to spot uplink ports (neighborport)
  my @fw_mac_list = ();
  foreach my $vlan (keys %{ $cache }) {
      foreach my $port (keys %{ $cache->{$vlan} }) {
          push @fw_mac_list, keys %{ $cache->{$vlan}->{$port} };
      }
  }
  @fw_mac_list = List::MoreUtils::uniq( @fw_mac_list );
  my $port_macs = get_port_macs(\@fw_mac_list);

  my $neighborport = {}; # ports through which we can see another device
  my $ignoreport   = {}; # ports suppressed by macsuck_no_deviceports

  if (scalar @{ setting('macsuck_no_deviceports') }) {
      my @ignoremaps = @{ setting('macsuck_no_deviceports') };

      foreach my $map (@ignoremaps) {
          next unless ref {} eq ref $map;

          foreach my $key (sort keys %$map) {
              # lhs matches device, rhs matches port
              next unless $key and $map->{$key};
              next unless acl_matches($device, $key);

              foreach my $port (sort { sort_port($a, $b) } keys %{ $device_ports }) {
                  next unless acl_matches($device_ports->{$port}, $map->{$key});

                  debug sprintf ' [%s] macsuck %s - port suppressed by macsuck_no_deviceports',
                    $device->ip, $port;
                  ++$ignoreport->{$port};
              }
          }
      }
  }


  foreach my $vlan (keys %{ $cache }) {
      foreach my $port (keys %{ $cache->{$vlan} }) {
          MAC: foreach my $mac (keys %{ $cache->{$vlan}->{$port} }) {

              unless (check_mac($mac, $device)) {
                  delete $cache->{$vlan}->{$port}->{$mac};
                  next MAC;
              }

              # this uses the cached $ports resultset to limit hits on the db
              my $device_port = $device_ports->{$port};

              # WRT #475 ... see? :-)
              unless (defined $device_port) {
                  debug sprintf
                    ' [%s] macsuck %s - port %s is not in database - skipping.',
                    $device->ip, $mac, $port;
                  delete $cache->{$vlan}->{$port}->{$mac};
                  next MAC;
              }

              if (exists $ignoreport->{$port}) {
                  debug sprintf
                    ' [%s] macsuck %s - port %s is suppressed by config - skipping.',
                    $device->ip, $mac, $port;
                  delete $cache->{$vlan}->{$port}->{$mac};
                  next MAC;
              }

              if (exists $neighborport->{$port}) {
                  debug sprintf
                    ' [%s] macsuck %s - seen another device thru port %s - skipping.',
                    $device->ip, $mac, $port;
                  delete $cache->{$vlan}->{$port}->{$mac};
                  next MAC;
              }

              my $neigh_cannot_macsuck = eval { # can fail
                acl_matches(($device_port->neighbor || "0 but true"), 'macsuck_unsupported') ||
                match_to_setting($device_port->remote_type, 'macsuck_unsupported_type') };

              # here, is_uplink comes from Discover::Neighbors finding LLDP remnants
              if ($device_port->is_uplink) {
                  if ($neigh_cannot_macsuck) {
                      debug sprintf
                        ' [%s] macsuck %s - port %s neighbor %s without macsuck support',
                        $device->ip, $mac, $port,
                        (eval { $device_port->neighbor->ip }
                         || ($device_port->remote_ip
                             || $device_port->remote_id || '?'));
                      # continue!!
                  }
                  elsif (my $neighbor = $device_port->neighbor) {
                      debug sprintf
                        ' [%s] macsuck %s - port %s has neighbor %s - skipping.',
                        $device->ip, $mac, $port, $neighbor->ip;
                      delete $cache->{$vlan}->{$port}->{$mac};
                      next MAC;
                  }
                  elsif (my $remote = $device_port->remote_ip) {
                      debug sprintf
                        ' [%s] macsuck %s - port %s has undiscovered neighbor %s',
                        $device->ip, $mac, $port, $remote;
                      # continue!!
                  }
                  elsif (not setting('macsuck_bleed')) {
                      debug sprintf
                        ' [%s] macsuck %s - port %s is detected uplink - skipping.',
                        $device->ip, $mac, $port;

                      $neighborport->{$port} = [ $vlan, $mac ] # remember neighbor port mac
                        if exists $port_macs->{$mac};
                      delete $cache->{$vlan}->{$port}->{$mac};
                      next MAC;
                  }
              }

              # here, the MAC is known as belonging to a device switchport
              if (exists $port_macs->{$mac}) {
                  my $switch_ip = $port_macs->{$mac};
                  if ($device->ip eq $switch_ip) {
                      debug sprintf
                        ' [%s] macsuck %s - port %s connects to self - skipping.',
                        $device->ip, $mac, $port;
                      delete $cache->{$vlan}->{$port}->{$mac};
                      next MAC;
                  }

                  debug sprintf ' [%s] macsuck %s - port %s is probably an uplink',
                    $device->ip, $mac, $port;
                  $device_port->update({is_uplink => \'true'});

                  if ($neigh_cannot_macsuck) {
                      # neighbor exists and Netdisco can speak to it, so we don't want
                      # its MAC address. however don't add to neighborport as that would
                      # clear all other MACs on the port.
                      delete $cache->{$vlan}->{$port}->{$mac};
                      next MAC;
                  }

                  # when there's no CDP/LLDP, we only want to gather macs at the
                  # topology edge, hence skip ports with known device macs.
                  if (not setting('macsuck_bleed')) {
                        debug sprintf ' [%s] macsuck %s - port %s is at topology edge',
                            $device->ip, $mac, $port;

                        $neighborport->{$port} = [ $vlan, $mac ]; # remember for later
                        delete $cache->{$vlan}->{$port}->{$mac};
                        next MAC;
                  }
              }

              # possibly move node to lag master
              if (defined $device_port->slave_of
                    and exists $device_ports->{$device_port->slave_of}) {

                  my $parent = $device_port->slave_of;
                  $device_ports->{$parent}->update({is_uplink => \'true'});

                  # VLAN subinterfaces can be set uplink,
                  # but we don't want to move nodes there (so check is_master).
                  if ($device_ports->{$parent}->is_master) {
                      delete $cache->{$vlan}->{$port}->{$mac};
                      ++$cache->{$vlan}->{$parent}->{$mac};
                  }
              }
          }
      }
  }

  # restore MACs of neighbor devices.
  # this is when we have a "possible uplink" detected but we still want to
  # record the single MAC of the neighbor device so it works in Node search.
  foreach my $port (keys %$neighborport) {
      my ($vlan, $mac) = @{ $neighborport->{$port} };
      delete $cache->{$_}->{$port} for keys %$cache; # nuke nodes on all VLANs
      ++$cache->{$vlan}->{$port}->{$mac};
  }

  return $cache;
}

true;
