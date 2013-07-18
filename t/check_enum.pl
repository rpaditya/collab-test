#!/usr/bin/perl
#
# based on 
# http://cpansearch.perl.org/src/SULLR/Net-SIP-0.66/samples/invite_and_recv.pl
# 
# this version does an ENUM lookup of a number given in the -n arg
# and records call details into an RRD (and outputs to STDERR)
# in ~/data/voip/
#
###########################################################################
# Invite other party, recv RTP data for some seconds or until other side
# hangs up, then BYE
# optional registration
#
# Most of the code is option parsing and usage, the Net::SIP related code
# is at the end
###########################################################################

use strict;

local $| = 1;
use warnings;
use IO::Socket::INET;
use Getopt::Long qw(:config posix_default bundling);

use Sys::Hostname;
my($hostname) = hostname;

use Time::HiRes;

use Net::SIP;
use Net::SIP::Util 'create_socket_to';
use Net::SIP::Debug;

require "${ENV{'HOME'}}/lib/monitor.pl";
our($config);
$config->{'STEP'} = 3600;

my($hasRRD) = 0;
eval {
  require RRDs;
};
unless ($@){
  $hasRRD = 1;
}

# this is where we update the RRDs
$config->{'dataDir'} = $ENV{'HOME'} . "/data/voip";

my(@timers);
my $callstart;
my $msgbuffer = "";

###################################################
# Get options
###################################################

my ($proxy,$outfile,$registrar,$username,$password,$hangup,$local_leg,$contact);
my (@routes,$debug, $verbose);
my ($from, $to, $num, @tos, $expected_return_status);
my(%opts);
GetOptions(%opts,
	'd|debug:i' => \$debug,
	'e|expected:s' => \$expected_return_status,
	'h|help' => sub { usage() },
	'P|proxy=s' => \$proxy,
	'R|registrar=s' => \$registrar,
	'O|outfile=s' => \$outfile,
	'T|time=i' => \$hangup,
	'L|leg=s' => \$local_leg,
	'C|contact=s' => \$contact,
	'username=s' =>\$username,
	'password=s' =>\$password,
	'route=s' => \@routes,
        'n|num=s' => \$num,
        'f|from=s' => \$from,
        't|to=s' => \$to,
        'v|verbose:i' => \$verbose,
) || usage( "bad option" );

my $script_command = $0;

# Net::SIP::Debug levels
#
#
#       1.  Debug messages for users
#       2.  Includes short SIP packet dumps of incoming and outgoing data
#       3.  Includes detailed SIP packet dumps for incoming and outgoing data
#       4.  Includes information about call flow, e.g. why packets get dropped
#           etc.
#       5.  Detailed debugging for programmers using Net::SIP.
#       6.  Detailed debugging for core developers of Net::SIP.

Net::SIP::Debug->level( $verbose || 0 ) if defined $verbose;
Net::SIP::Debug->import(\&prenotify);

$config->{'DEBUG'} = $debug;

my $callstatus = 100;

my(%expected);
if (defined $expected_return_status){
  for my $e (split(',', $expected_return_status)){
    $expected{$e} = $e;
  }
} else {
  $expected{200} = 200;
}

sub update {
  my($type) = shift(@_);

  my($RRD);
  my($STEP) = $config->{'STEP'};

  next if (!defined($type) || $type eq "");
  if ($type eq "sip") {
    $RRD = shift(@_);
  }
  my(@vals) = @_;

  my($t) = time;
  $t = int($t);

  if ($config->{'DEBUG'}) {
    notify('debug', "hasRRD is ${hasRRD}");
    my($msg) = "updateRRD(${RRD}, ${t}, " . join(", ", @vals) . ")";
    notify('debug', $msg);
  } else {
    if ($hasRRD){
      if (! -e $RRD) {
	my($START) = time - (2 * $STEP);

	notify('info', "Creating $RRD with step ${STEP} starting at $START");
	my($v, $msg) = RRD_create($RRD, $START, $STEP, $type);
	if ($v) {
	  notify('err', "couldn't create $RRD because $msg");
	  return;
	}
      }

      my($rv, $errmsg) = updateRRD($RRD, $t, @vals);
      if ($rv) {
	notify('err', "error updating $RRD : ${errmsg}");
      }
    }
  }
}

sub RRD_create {
    my($RRD, $START, $interval, $type) = @_;
    my(@dses);
    my(@rras) = (
                 "RRA:AVERAGE:0.5:1:3000",
                 "RRA:MAX:0.5:1:3000",
                 "RRA:AVERAGE:0.5:5:3000",
                 "RRA:MAX:0.5:5:3000",
                 "RRA:AVERAGE:0.5:10:5000",
                 "RRA:MAX:0.5:10:5000",
                 "RRA:AVERAGE:0.5:1440:732",
                 "RRA:MAX:0.5:1440:732"
                 );
    if ($type eq "tr"){
      @dses = (
	       "DS:totalhops:GAUGE:7200:U:U",
	       "DS:totalt:GAUGE:7200:U:U",
	      );
      for (my $i=1;$i<=20;$i++){
	push(@dses, "DS:hop${i}t:GAUGE:7200:U:U");
      }
    } elsif ($type eq "sip"){
      @dses = (
	       "DS:nslookup:GAUGE:7200:U:U",
	       "DS:setupt:GAUGE:7200:U:U",
	       "DS:totalcallt:GAUGE:7200:U:U",
	       "DS:status:GAUGE:7200:U:U",
	       "DS:rtpbytes:GAUGE:7200:U:U",
	      );
    } else {
        notify('ERR', "could not create RRD of type ${type}");
        return(1, "do not recognize type ${type}");
    }

    if ($config->{'DEBUG'}){
      notify('debug', "not creating RRD ${RRD} because debug is > 6");
    } else {
      RRDs::create ("$RRD", "-b", $START, "-s", $interval, @dses, @rras);

      if (my $error = RRDs::error()) {
          return(1, "Cannot create $RRD: $error");
      } else {
	return(0, "$RRD");
      }
    }
}

sub usage {
	print STDERR "ERROR: @_\n" if @_;
	print STDERR <<EOS;
usage: $0 [ options ] FROM TO
Makes SIP call from FROM to TO, optional record data
and optional hang up after some time
Options:
  -d|--debug [level]           Enable debugging
  -e|--expected=[sip status],XXX,XXX   SIP call status code (multiple separated by commas)
  -v|--verbose                 Verbose (show debug info even if no error)
  -h|--help                    Help (this info)
  -n +91803312465              number in E.164 format with starting "+"
  -f sipuri                    from SIP URI starting with "sip:", defaults to \$USERNAME
  -t sipuri                    SIP URI starting with "sip:" (overriden by -n)
  -P|--proxy host[:port]       use outgoing proxy, register there unless registrar given
  -R|--registrar host[:port]   register at given address
  -O|--outfile filename        write received RTP data to file
  -T|--time interval           hang up after interval seconds
  -L|--leg ip[:port]           use given local ip[:port] for outgoing leg
  -C|--contact sipaddr         use given contact address for contact in register and invite
  --username name              username for authorization
  --password pass              password for authorization
  --route host[:port]          add SIP route, can be specified multiple times

Examples:
  $0 -T 10 -O record.data sip:30\@192.168.178.4 sip:31\@192.168.178.1
  $0 --username 30 --password secret --proxy=192.168.178.3 sip:30\@example.com 31
  $0 --username 30 --password secret --leg 192.168.178.4 sip:30\@example.com 31

EOS
	exit( @_ ? 1:0 );
}

# put all output in this var and only display if debug is on and things fail
my($msgout);

sub Vdie {
   my ($echo,$vr)=@_;
   print ("Fatal error: " . $vr . ": " . $echo);
   exit 0;
}

if (defined $from){
  if ($from =~ /^sip\:/){
  } else {
    $from = "sip:" . $from ;
  }
} else {
  $from = "sip:" . $ENV{'USER'} . "\@" . $hostname;
}

if (defined $num && $num =~ /\+?\d+/){

  $script_command .= " -n ${num}";

  # put in the RRD name
  my($RRDname) = "$config->{'dataDir'}/enum${num}.rrd";
  push(@timers, $RRDname);
  notify('debug', "pushed ${RRDname} onto timers");

  # which enum trees to traverse looking for mappings
  my(@tree) = (
	       "nrenum.net", 
	       "e164.org", 
	       "e164.arpa"
	      );

  for my $t (@tree){
    notify("debug", "looking up ${num} in ${t}");
    my($start) = Time::HiRes::time ();
    my(@test) = naptr_query($num, $t);
    my($end) = Time::HiRes::time ();
    #nslookupt 1
    my($nslookupt) = ($end - $start);

  LOOKUP: {
      for my $x ( 0 .. $#test ) {
	if (my $aref = $test[$x]) {
	  my $y = @$aref - 1;
	  for my $z ( 0 .. $y ) {
	    if ($test[$x][$z]) {
	      notify("debug", "${x} ${z} $test[$x][$z]");
	      # only try sip calls
	      if ($test[$x][$z] =~ /^sip\:/i){
		push(@tos, $test[$x][$z]);
		push(@timers, $nslookupt);
		notify('debug', "pushed nslookupt ${nslookupt} onto timers");
		last LOOKUP;
	      }
	    }
	  }
	}
      }
    }
  }

  if ($#tos < 0){
    my($lookup_err) = "FAIL in DNS lookup: No sip route found to ${num}";
    notify('debug', $lookup_err);
    $msgbuffer .= $lookup_err . "\n";
    $callstatus = 488;
  }

} elsif (defined $to){
  if ($to !~ /^\w+\:/){
    $to = "sip:" . $to;
  }
  push(@tos, $to);
  $script_command .= " -t ${to}";
  my($filename) = $to;
  $filename =~ s/\:/\./g;
  my($RRDname) = "$config->{'dataDir'}/${filename}.rrd";
  notify('debug', "pushed ${RRDname} onto timers");
  push(@timers, $RRDname);
  # nslookupt 1
  push(@timers, 0);
  notify('debug', "no need for nslookup, given sip to, so pushing nslookupt of 0 onto timers");
} else {
  usage( "no target; please define an e164 number to call or provide a sip to" );
}

# we run this here after all necessary args are added, don't move
&prenotify("running ${script_command}");

# register at proxy if proxy given and no registrar
$registrar ||= $proxy;

###################################################
# find local leg
###################################################
my ($local_host,$local_port);
if ( $local_leg ) {
	($local_host,$local_port) = split( m/:/,$local_leg,2 );
} elsif ( ! $proxy ) {
	# if no proxy is given we need to find out
	# about the leg using the IP given from FROM
	($local_host,$local_port) = $from =~m{\@([\w\-\.]+)(?::(\d+))?}
		or Vdie ("cannot find SIP domain in '$from'",3);
}

my $leg;
if ( $local_host ) {
	my $addr = gethostbyname( $local_host )
		|| Vdie ("cannot get IP from SIP domain '$local_host'",3);
	$addr = inet_ntoa( $addr );

	$leg = IO::Socket::INET->new(
		Proto => 'udp',
		LocalAddr => $addr,
		LocalPort => $local_port || 5060,
	);

	# if no port given and port 5060 is already used try another one
	if ( !$leg && !$local_port ) {
		$leg = IO::Socket::INET->new(
			Proto => 'udp',
			LocalAddr => $addr,
			LocalPort => 0
		) || Vdie ("cannot create leg at $addr: $!",3);
	}

	$leg = Net::SIP::Leg->new( sock => $leg );
}

###################################################
# SIP code starts here
###################################################

# create necessary legs
# If I have an only outgoing proxy I could skip this step because constructor
# can make leg to outgoing_proxy itself
my @legs;
push @legs,$leg if $leg;
foreach my $addr ( $proxy,$registrar) {
	$addr || next;
	if ( ! grep { $_->can_deliver_to( $addr ) } @legs ) {
		my $sock = create_socket_to($addr) || Vdie ("cannot create socket to $addr",3);
		push @legs, Net::SIP::Leg->new( sock => $sock );
	}
}

# create user agent
my $ua = Net::SIP::Simple->new(
	from => $from,
	outgoing_proxy => $proxy,
	route => \@routes,
	legs => \@legs,
	$contact ? ( contact => $contact ):(),
	$username ? ( auth => [ $username,$password ] ):(),
);

# optional registration
if ( $registrar && $registrar ne '-' ) {
	$ua->register( registrar => $registrar );
	Vdie ("registration failed: ".$ua->error,1) if $ua->error
}

my $stopvar;

sub final {
  my ($status,$self,%info) = @_;
  my($end) = Time::HiRes::time ();

  notify("debug", "call status: ${status}");

  for my $i (keys %info){
    notify("debug", "${i}: $info{$i}");
  }

  my $setupComplete = ($end - $callstart);
  if ($#timers >= 3 && $timers[2] == $hangup){
    pop(@timers);
  }
  push(@timers, $setupComplete);
  notify('debug', "pushing setupt ${setupComplete} onto timers");

  if (defined $info{"code"}){
  } else {
    $info{"code"} = 200;
  }

  $callstatus = $info{"code"};

  return;
}

# invite peer
my $peer_hangup; # did peer hang up?

sub peerHangup {
  $peer_hangup = 1;
  notify('debug', "Peer hangup, timeout");
  &expiredTimer();
}

sub expiredTimer {
  if (! defined $callstatus || (defined $callstatus && $callstatus == 180)){
    notify('debug', "Timeout, setting status to 408");
    $callstatus = 408;
  }
}

sub prelim {
  &noanswer(@_);
}

sub noanswer {
  my ($self,$code,$response) = @_;
  if (! defined $code){
    notify('debug', "Preliminary answer to INVITE sent, 100 Trying");
    $callstatus = 100;
  } else {
    $callstatus = $code;
  }
  return;
}

#my $echo_10 = Net::SIP::Simple->rtp('media_recv_echo', $outfile, 0);
#			  init_media => $echo_10,

if (defined $outfile){
} else {
  $outfile = "/dev/null";
}
notify('debug', "rtp output file is set to ${outfile}");

sub dtmf {
  my ($event, $duration) = @_;
  notify('debug', "received DTMF ${event} for duration of ${duration}");
}

for my $to (@tos){
  notify("debug", " calling ${to}");
  $callstart = Time::HiRes::time ();

##
  my $call = $ua->invite( $to,
			  # echo back, use -1 instead of 0 for not echoing back
			  init_media => $ua->rtp( 'media_recv_echo', $outfile, 0),
#			  recv_bye => \&peerHangup,
			  recv_bye => \$peer_hangup,
			  cb_final => \&final,
#			  cb_preliminary => \&prelim,
			  cb_noanswer => \&noanswer,
			  cb_dtmf => \&dtmf,
			);

  # mainloop until other party hangs up or we hang up after $hangup seconds
  # add_timer ( WHEN, CALLBACK, [ REPEAT ] )
  if (! $peer_hangup){
    $ua->add_timer( $hangup, \$stopvar ) if $hangup;
  }

  # loop ( [ TIMEOUT, @STOPVAR ] ), stop if any var in @STOPVAR evals to true
  $ua->loop(\$stopvar, \$peer_hangup );

  # timeout, I need to hang up
  if ( $stopvar ) {
    $stopvar = undef;
    $call->bye( cb_final => \&final );
    $stopvar = 1;
    $ua->loop( \$stopvar );
  }
##

  # if the call doesn't timeout but the setup never completes
  # we need to add a setup time in any case
  if ($#timers < 3 && $callstatus == 100){
    push(@timers, $hangup);
  }

  my($end) = Time::HiRes::time ();
  # totalcallt
  my($totalcallt) = ($end - $callstart);
  push(@timers, $totalcallt);
  notify('debug', "pushing total call t ${totalcallt} onto timers");
  # status
  push(@timers, $callstatus);
  notify('debug', "pushing status of ${callstatus} onto timers");

  # RTP filesize 
  if (-e $outfile){
    my($size) = getFileSizeB($outfile);
    push(@timers, $size);
  } else {
    push(@timers, 0);
  }

  update("sip", @timers);

  notify("debug", "CALL returned: ${callstatus}");
}

# by default expected_return_status is 200
if (! defined $expected{$callstatus}){
  print "\nERROR: Expected call status of " . join(',', (keys %expected)) . " but got ${callstatus} instead\n";
  print "\n" . $msgbuffer;
  for (my $n=1;$n<=80;$n++){
    print "-";
  }
  print "\n";
}

### Add enum lookup code ###
### from http://cpansearch.perl.org/src/JAMESGOL/asterisk-perl-1.03/examples/agi-enum.agi ###

sub naptr_query {
	my ($lookup, $domain) = @_;

	my $dns = Net::DNS::Resolver->new;
	my $name = reversenum($lookup) . '.' . $domain;

	notify("debug", "looking up ${name}");

	my $query = $dns->search($name, 'NAPTR');
	my @hosts;
	if ($query) {
		foreach my $rr ($query->answer) {
			next unless $rr->type eq "NAPTR";
			my $order = $rr->order;
			my $pref = $rr->preference;
			if ($rr->flags !~ /u/i) {
				next;
			}
			foreach my $svct (split(/\+/,$rr->service)) {
				next if ($svct =~ /E2U/i);
				next if (!validprotocol($svct));
			}

			my($host);
			if ($rr->replacement && $rr->replacement ne ".") {
			  notify("debug", $rr->replacement);
			  $host = naptr_replace($rr->replacement, $rr->regexp, $lookup);
			} else {
				$host = naptr_regexp($rr->regexp, $lookup);
			}

			notify("debug", $order . ": " . $pref . " " . $host . $rr->regexp . " " . $rr->replacement);
			$hosts[$order][$pref] = $host;
		}
	} else {
	  notify("debug", $dns->errorstring);
	}
	return @hosts;
}

sub naptr_replace {
	my ($replace, $regex, $number) = @_;

	return $replace;
}

sub naptr_regexp {
	my ($string, $number) = @_;

	notify("debug", "going to do regexp substitution of ${string} on ${number}");

	my $regex = '';
	my $data = '';
	my $delim;
	if ($string =~ /^(.).*(.)$/) {
		$delim = $1 if ($1 eq $2);
		notify("debug", "found regexp delimiter of \"${delim}\"");
	} else {
		return '';
	}
	if ($string =~ /$delim(.*)$delim(.*)$delim/) {
		my $regex = $1;
		$data = $2;
		notify("debug", "regex: ${regex} data: ${data}");
		if ($regex) {
		  my($t);
			if ($number =~ /$regex/) {
			  notify("debug", "first: " . $1);
				if ($t = $1) { $data =~ s/\\1/$t/g; }
				if ($t = $2) { $data =~ s/\\2/$t/g; }
				if ($t = $3) { $data =~ s/\\3/$t/g; }
				if ($t = $4) { $data =~ s/\\4/$t/g; }
				if ($t = $5) { $data =~ s/\\5/$t/g; }
				if ($t = $6) { $data =~ s/\\6/$t/g; }
				if ($t = $7) { $data =~ s/\\7/$t/g; }
				if ($t = $8) { $data =~ s/\\8/$t/g; }
				if ($t = $9) { $data =~ s/\\9/$t/g; }
			}
		}
	}

	notify("debug", "data ${data}");

	return $data;
	
}


sub reversenum {
        my ($num) = @_;

	#remove all non numeric
	$num =~ s/[^0-9]//g;
	return join('.', split(/ */, reverse($num)));
}

my @PROTOCOLS = (
	      'iax',
	      'sip',
	      'tel' 
	      #	'h323'
	     );

sub validprotocol {
	my ($prot) = @_;

	my $valid = 0;

	foreach (@PROTOCOLS) {
		if (m/$prot/i) {
			$valid = 1;
		}
	}
	return $valid;
}

sub prenotify {
  my($msg) = @_;
  if ($verbose){
    $msgbuffer .= $msg . "\n";
    notify("debug", $msg);
  }
}

sub getFileSizeB {
  my($f) = @_;
  my ($dev,$ino,$mode,$nlink,$uid,$gid,$rdev,$size,$atime,$mtime,$ctime,$blsize,$blocks) = stat($f);
  return sprintf("%.02f", $size);
}

