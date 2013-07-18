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
my($DEBUG) = 0;
GetOptions(%opts,
	   'd|debug:i' => \$DEBUG,
	  ) || usage( "bad option" );

sub usage {
  print STDERR "ERROR: @_\n" if @_;
  print STDERR <<EOS;
usage: $0 [ options ] E.164_number
Does lookups to see if E.164_number is present in any enum tree
and if so resolves it
Options:
  -d|--debug [level]           Enable debugging
EOS
  exit( @_ ? 1:0 );
}

use Net::DNS;
my $res = Net::DNS::Resolver->new;

my @PROTOCOLS = (
		 'iax',
		 'sip',
		 'tel' 
		 #	'h323'
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
  for my $x ( 0 .. $#test ) {
    if (my $aref = $test[$x]) {
      my $y = @$aref - 1;
      for my $z ( 0 .. $y ) {
	if ($test[$x][$z]) {
	  print <<LLI;
$x $z $test[$x][$z]
LLI
	}
      }
    }
  }
}
my(@timers);

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
	if ($DEBUG) {
	  my($end) = Time::HiRes::time();
	  push(@timers,$end);
	  print STDERR "${end}: " . $rr->replacement . "\n";
	}
	$host = naptr_replace($rr->replacement, $rr->regexp, $lookup);
      } else {
	if ($DEBUG) {
	  my($end) = Time::HiRes::time();
	  push(@timers,$end);
	  print STDERR "${end}: RR-replacement value was undef or ., searching deeper\n";
	}
	$host = naptr_regexp($rr->regexp, $lookup);
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
