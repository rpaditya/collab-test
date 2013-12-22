#!/usr/bin/perl -w

local $| = 1;
use strict;

use Net::SIP;
use Net::SIP::Debug;

use Getopt::Long qw(:config posix_default bundling);
my($verbose, $proxy, $registrar, $password, $username, $debug, $outfile, $port);
my(%opts);
GetOptions(%opts,
	'd|debug:i' => \$debug,
	'h|help' => sub { usage() },
	'P|proxy=s' => \$proxy,
	'R|registrar=s' => \$registrar,
	'O|outfile=s' => \$outfile,
        'port:i' => \$port,
	'username=s' =>\$username,
	'password=s' =>\$password,
        'v|verbose:i' => \$verbose,
) || usage( "bad option" );

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

Net::SIP::Debug->level( $debug || 0 ) if defined $debug;

sub usage {
	print STDERR "ERROR: @_\n" if @_;
	print STDERR <<EOS;
usage: $0 [ options ] FROM TO
Makes SIP call from FROM to TO, optional record data
and optional hang up after some time
Options:
  -d|--debug [level]           Enable debugging
  -v|--verbose                 Verbose (show debug info even if no error)
  -h|--help                    Help (this info)
  -P|--proxy host[:port]       use outgoing proxy, register there unless registrar given
  -R|--registrar host[:port]   register at given address
  -O|--outfile filename        send RTP data from file
  --username name              username for authorization
  --password pass              password for authorization
  --port 5062                  port to use for incoming signaling

Examples:
  $0 --username 30 --password secret --registrar=192.168.178.3 -O foo.rtp

EOS
	exit( @_ ? 1:0 );
}

if (defined $proxy){
} else {
  $proxy = $registrar;
}

if (defined $port){
} else {
  $port = 5062;
}

# create new agent
my $ua = Net::SIP::Simple->new(
  outgoing_proxy => $proxy,
  registrar => $registrar,
  domain => $registrar,
  from => $username,
  auth => [ $username, $password ],
  port => $port,
);

my($reg_expires) = 190;
sub regme {
        # Register agent
        $ua->register(expires => $reg_expires,
                      cb_final => \&rereg
                      );
      }

sub rereg {
        print "Registered, expires ${reg_expires}\n";
        $ua->add_timer($reg_expires, \&regme);
      }

sub who {
#       Net::SIP::Simple::Call=HASH(0x28494b40)|
#       Net::SIP::Request=HASH(0x2848876c)|
#       Net::SIP::Leg=HASH(0x288af3ac)|
#       134.215.222.243:5060
        my($call, $request, $leg, $netid) = @_;
        my($other) = $request->uri;
        my($method) = $request->method;
        my($when) = $request->get_header("Date");
        my($from) = $request->get_header("From");

	if (defined $verbose){
	  print "Received call from ${netid}";
	  print "|${other}";
	  print "|${method}";
	  print "|${when}|${from}";
	  print "|" . $request->dump(10);
	  print "|\n";
	}

#	if (defined $outfile && -r $outfile){
#	  if (defined $verbose){
#	    print "sending rtp ${outfile} \n";
#	  }
#	  my $rtp = $call->rtp('media_send_recv',$outfile,1,"/dev/null");
#	} else {
#	  my $rtp = $call->rtp('media_recv_echo');
#	}
        return 1;
      }

sub peerHangup {
  if (defined $verbose){
    print "peer hangup!\n";
  }
}

&regme;
my $call_closed;
$ua->listen(
	    cb_create => \&who,
	    cb_established => sub { print( 'call established' ) },
	    cb_cleanup => sub {
	      print ( 'call cleaned up' );
	      $call_closed = 1;
	    },  
            init_media => $ua->rtp( 'recv_echo' ),
            recv_bye => \&peerHangup,
	   );


# Mainloop
$ua->loop();
