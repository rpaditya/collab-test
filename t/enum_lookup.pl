#!/usr/bin/perl -w
#
# very simple DNS lookup script that returns the necessary
# details from an NAPTR record on an enum lookup of a e.164 number
# passed in as an arg, ie.
# 
# ./enum_lookup.pl +9999213
#

use strict;
local $| = 1;

use Time::HiRes;

use Getopt::Long qw(:config posix_default bundling);
my(%opts);
my($genzones);
my($DEBUG) = 0;
GetOptions(%opts,
	   'd|debug:i' => \$DEBUG,
	   'g|genzones' => \$genzones,
	  ) || usage( "bad option" );

sub usage {
  print STDERR "ERROR: @_\n" if @_;
  print STDERR <<EOS;
usage: $0 [ options ] E.164_number
Does lookups to see if E.164_number is present in any enum tree
and if so resolves it
Options:
  -d|--debug [level]           Enable debugging
  -g|--genzones                Generate wildcard zones for entire number
EOS
  exit( @_ ? 1:0 );
}

use Net::DNS;
my $res = Net::DNS::Resolver->new;

my @PROTOCOLS = (
		 'iax',
		 'sip',
		 'tel',
		 'h323',
		);


my(@tree) = (
	     "nrenum.net", 
	     "e164.org", 
	     "e164.arpa"
	    );

my($num) = @ARGV;
chomp $num;

for my $t (@tree) {
  my(@test) = naptr_query($num, $t);
  for my $x ( 0 .. ($#test) ) {
    if ($DEBUG){
      print STDERR "DEBUG: x loop step " . $x . "\n";
    }
    if (my $aref = $test[$x]) {
      if ($DEBUG){
	print STDERR "DEBUG: " . join('|', $test[$x]) . "\n";
      }
      my $y = @$aref - 1;
      if ($DEBUG){
	print STDERR "DEBUG: y loop step " . $y . "\n";
      }
      for my $z ( 0 .. $y ) {
	if ($test[$x][$z]) {
	  print <<LLI;
$x $z $test[$x][$z]
LLI

	  if (defined $genzones){
	    genz($num, $t, $x, $z, $test[$x][$z]);
	  }

	}
      }
    }
  }
}
my(@timers);

sub genz {
  my($n, $t, $priority, $weight, $dest) = @_;
  my($name) = reversenum($n);
  my(@digits) = split(/\./, $name);

  if ($DEBUG){
    print STDERR "Generating wildcards to complement exceptions\n";
    print STDERR "starting at " . $name . "\n";
  }

  for (my $i=0;$i<=$#digits;$i++){
    shift(@digits);
    if ($DEBUG){
      print STDERR "now at i=${i}: " . join('.', @digits) . "\n";
    }
    for (my $j=0; $j<=9; $j++){
      if ($DEBUG){
	print STDERR "now at j=${j}: " . join('.', @digits) . "\n";
      }

# generic BIND format
#      print "*." . $j . "." . join('.', @digits) . "." . $t . " IN NAPTR ${priority} ${weight}  ${dest}\n";

      my($ttl) = 3600;
#      my($regexp) = '!^(.*)$!h323:\\1@h323.video.collab.it.umich.edu!';
      my($regexp) = '!^(.*)$!sip:\\1@enum.voice.collab.it.umich.edu!';

# Proteus bulk csv upload format
#add, srv.example.com., 3600, SRV, 10 0 50 host1.example.com, An SRV record
#add, *.1.6.2.3.6.7.4.3.7.1.nrenum.net., 3600, NAPTR, 100 10 E2U+email !^.*$!mailto:information@example.com!i . A
      print "add, *." . $j . "." . join('.', @digits) . "." . $t . ", ${ttl}, NAPTR, ${priority} ${weight} E2U+sip ${regexp} . u\n";
    }
  }
}

sub naptr_query {
  my ($lookup, $domain) = @_;

  my $dns = Net::DNS::Resolver->new;
  my $name = reversenum($lookup) . '.' . $domain;

  if ($DEBUG) {
    my($start) = Time::HiRes::time();
    push(@timers,$start);
    print STDERR "${start}: looking up NAPTR for ${name}\n";
  }

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
	$host = naptr_replace($rr->replacement, $rr->regexp, $lookup);
	if ($DEBUG) {
	  my($end) = Time::HiRes::time();
	  push(@timers,$end);
	  print STDERR "${end}: " . $rr->replacement . "\n";
	  print STDERR "DEBUG: " . $host;
	}
      } else {
	$host = naptr_regexp($rr->regexp, $lookup);
	if ($DEBUG) {
	  my($end) = Time::HiRes::time();
	  push(@timers,$end);
	  print STDERR "${end}: RR-replacement value was undef or ., searching deeper\n";
	  print STDERR "DEBUG: " . $host;
	}
      }
      if ($DEBUG) {
	my($end) = Time::HiRes::time();
	push(@timers,$end);

	print STDERR "${end}: " . $order . ": " . $pref . " " . $host . $rr->regexp . " " . $rr->replacement . "\n";
      }
      $hosts[$order][$pref] = $host;
    }
  } else {
    if ($DEBUG) {
      my($end) = Time::HiRes::time();
      push(@timers,$end);
      print STDERR "${end}: got back " . $dns->errorstring . "\n";
    }
  }
  return @hosts;
}

sub naptr_replace {
  my ($replace, $regex, $number) = @_;

  return $replace;
}

sub naptr_regexp {
  my ($string, $number) = @_;

  if ($DEBUG) {
    print STDERR "going to do regexp substitution of ${string} on ${number}\n";
  }

  my $regex = '';
  my $data = '';
  my $delim;
  if ($string =~ /^(.).*(.)$/) {
    $delim = $1 if ($1 eq $2);
    if ($DEBUG) {
      print STDERR "found regexp delimiter of \"${delim}\"\n";
    }
  } else {
    return '';
  }
  if ($string =~ /$delim(.*)$delim(.*)$delim/) {
    my $regex = $1;
    $data = $2;
    if ($DEBUG) {
      print STDERR "regex: ${regex} data: ${data} \n";
    }
    if ($regex) {
      my($t);
      if ($number =~ /$regex/) {
	if ($DEBUG) {
	  print STDERR "first: " . $1 . "\n";
	}
	if ($t = $1) {
	  $data =~ s/\\1/$t/g;
	}
	if ($t = $2) {
	  $data =~ s/\\2/$t/g;
	}
	if ($t = $3) {
	  $data =~ s/\\3/$t/g;
	}
	if ($t = $4) {
	  $data =~ s/\\4/$t/g;
	}
	if ($t = $5) {
	  $data =~ s/\\5/$t/g;
	}
	if ($t = $6) {
	  $data =~ s/\\6/$t/g;
	}
	if ($t = $7) {
	  $data =~ s/\\7/$t/g;
	}
	if ($t = $8) {
	  $data =~ s/\\8/$t/g;
	}
	if ($t = $9) {
	  $data =~ s/\\9/$t/g;
	}
      }
    }
  }

  if ($DEBUG) {
    print STDERR "data ${data}\n";
  }

  return $data;
	
}


sub reversenum {
  my ($num) = @_;

  #remove all non numeric
  $num =~ s/[^0-9]//g;
  my($numjoined) = join('.', split(/ */, reverse($num)));
  if ($DEBUG) {
    print STDERR " ${num} -> ${numjoined} \n";
  }
  return $numjoined;
}


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
