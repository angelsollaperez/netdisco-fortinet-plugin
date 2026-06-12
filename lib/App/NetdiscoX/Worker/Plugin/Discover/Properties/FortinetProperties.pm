package App::NetdiscoX::Worker::Plugin::Discover::Properties::FortinetProperties;

use Dancer ':syntax';
use App::Netdisco::Worker::Plugin;
use aliased 'App::Netdisco::Worker::Status';

use App::Netdisco::Transport::SNMP ();
use App::Netdisco::Util::Permission qw/acl_matches acl_matches_only/;
use App::Netdisco::Util::FastResolver 'hostnames_resolve_async';
use App::Netdisco::Util::Device 'get_device';
use App::Netdisco::Util::DNS 'hostname_from_ip';
use App::Netdisco::Util::SNMP 'snmp_comm_reindex';
use App::Netdisco::Util::Web 'sort_port';
use App::Netdisco::DB::ExplicitLocking ':modes';

use Dancer::Plugin::DBIC 'schema';
use Scope::Guard 'guard';
use NetAddr::IP::Lite ':lower';
use Storable 'dclone';
use List::MoreUtils ();
use JSON::PP ();
use Encode; 

# -------------------------------------------------------------
# Custom SNMP model and os_ver - override defaults
# -------------------------------------------------------------
use strict;
use warnings;
use Exporter;
use SNMP::Info::Layer3;
use SNMP::Info::Aggregate 'agg_ports_ifstack';

@SNMP::Info::Layer3::Fortinet::ISA = qw/
    SNMP::Info::Layer3
    SNMP::Info::Aggregate
    Exporter
/;
@SNMP::Info::Layer3::Fortinet::EXPORT_OK = qw//;

our ($VERSION, %GLOBALS, %FUNCS, %MIBS, %MUNGE);

$VERSION = '3.972002';

%MIBS = (
    %SNMP::Info::Layer3::MIBS,
    %SNMP::Info::Aggregate::MIBS,
    'FORTINET-CORE-MIB'      => 'fnSysSerial',
    'FORTINET-FORTIMANAGER-FORTIANALYZER-MIB' => 'fmSysVersion',
    'FORTINET-FORTIAUTHENTICATOR-MIB' => 'facSysVersion',
    'FORTINET-FORTISWITCH-MIB' => 'fsSysVersion',
);

%GLOBALS = (
    %SNMP::Info::Layer3::GLOBALS,
);

%FUNCS = (
    %SNMP::Info::Layer3::FUNCS,
);

%MUNGE = (
    %SNMP::Info::Layer3::MUNGE,
);

sub model_plugin {
    my $fortinet = shift;
    my $id = $fortinet->id() || '';
    
    my $model = &SNMP::translateObj($id);

    if (defined $model && ($model =~ /^\d+(\.\d+)*$/ || $model =~ /common/i)) {
        my $ver = $fortinet->fsSysVersion() || '';

        # search for Forti-MODEL-SUFFIX followed by whitespace
        if ($ver =~ /^(Forti\S*)/) {
            return $1;
        }
        
        # if not, extract numeric model (e.g., 248E)
        if ($ver =~ /\b(\d+[A-Z]*)\b/) {
            return $1;
        }
    }
    return $id unless defined $model;

    $model =~ s/^f[grsw][tfw]?//i;
    return $model;
}


sub os_ver_plugin {
    my $fortinet = shift;

    # Try the first three + AP functions for version
    my $ver = $fortinet->fgSysVersion() 
            || $fortinet->fmSysVersion() 
            || $fortinet->facSysVersion();

    # If no version is found, try fsSysVersion
    if (!$ver) {
        my $versys = $fortinet->fsSysVersion() || '';
        
        # Extract version in the format vX.X.X or X.X.X
        if ($versys =~ /(?:v)?(\d+\.\d+\.\d+)/) {
            return $1;
        }
    }

    # If no version is found, try fapVersion
    if (!$ver) {
        my $versys = $fortinet->fapVersion() || '';
        

        # Extract version in the format vX.X.X or X.X.X
        if ($versys =~ /(?:v)?(\d+\.\d+(?:\.\d+)?)/) {
            return $1;
        }
    }

    if (defined $ver) {
        if ($ver =~ /(\d+[\.\d]+)/) {
            return $1;
        } else {
            return $ver;
        }
    }
    return;
}

# -------------------------------------------------------------
# Run worker after the existing stages and replace
# model and os_ver if existing ones are incorrect
# -------------------------------------------------------------


register_worker({ phase => 'user', driver => 'snmp' }, sub {
  my ($job, $workerconf) = @_;

  my $device = $job->device;
  return unless $device->vendor =~ /fortinet/i;
  
  my $snmp = App::Netdisco::Transport::SNMP->reader_for($device)
    or return Status->defer("discover failed: could not SNMP connect to $device");


  my $now = vars->{'timestamp'};
  my $hostname = hostname_from_ip($device->ip);
  $device->set_column( dns => $hostname ) if $hostname;

  if (!defined $device->model || $device->model =~ /common|fortinet/i) {
    my $model = model_plugin($snmp);
    ($model = Encode::decode('UTF-8', ($model || ''))) =~ s/\s+$//;
    debug "Updated Model: $model";
    $device->set_column(model => $model);
  }

  # Check and update OS version if undefined or not in 'number.dots' format
  if (!defined $device->os_ver || $device->os_ver !~ /^\d+\.\d+(\.\d+)*$/) {
      my $os_ver = os_ver_plugin($snmp) || "";
      debug "Updated OS Version: $os_ver";
      $device->set_column(os_ver => $os_ver);
  }

  # protection for failed SNMP gather
  if ($device->in_storage and not $device->is_pseudo) {
      my $ip = $device->ip;
      my $protect = setting('snmp_field_protection')->{'device'} || {};
      my %dirty = $device->get_dirty_columns;
      foreach my $field (keys %dirty) {
          next unless acl_matches_only($ip, $protect->{$field});
          if (!defined $dirty{$field} or $dirty{$field} eq '') {
              return $job->cancel("discover cancelled: $ip failed to return valid $field");
          }
      }
  }
  
  schema('netdisco')->txn_do(sub {
    $device->update_or_insert(undef, {for => 'update'});
    return Status->info("Ended additional Model, OS discover for Fortinet $device");
  });
});

true;
