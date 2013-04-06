# Copyright (C) 2000-2013 by R.P. Aditya <aditya@grot.org>
# (See "License", below.)
#
# License:
#    This program is free software; you can redistribute it and/or
#    modify it under the terms of the GNU General Public License
#    as published by the Free Software Foundation; either version 2
#    of the License, or (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You may have received a copy of the GNU General Public License
#    along with this program; if not, write to the Free Software
#    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307,
#    USA.
#
#    An on-line copy of the GNU General Public License can be found
#    http://www.fsf.org/copyleft/gpl.html.

use strict;
local $| = 1;

use vars qw($config);

use Digest::MD5  qw(md5 md5_hex md5_base64);
use Time::HiRes;
use LWP::UserAgent;
use Sys::Syslog;
#Sys::Syslog::setlogsock('unix');
use RRDs;

$config->{'STEP'} = 300;
$config->{'DEBUG'} = 0;
$config->{'timeout'} = 15;
if (! defined $main::config->{'logfacility'}){
    $config->{'logfacility'} = 'user';
}

sub check_httpd {
    my($url, $username, $pwd, $timeout) = @_;
    my($rval) = 0;

    my($ua) = new LWP::UserAgent;
    $ua->timeout($timeout);

    my($start) = Time::HiRes::time ();
    my($request) = HTTP::Request->new(GET => $url);
    my($tcp_end) = Time::HiRes::time ();
    $request->authorization_basic($username, $pwd);
    my($response) = $ua->request($request);
    my($finish) = Time::HiRes::time ();
    my($content) = $ua->request($request)->content;
    $rval = $response->is_success - $response->is_error;
    my($contentsize) = length($content);
    my($md5) = md5_base64($content);

    undef $ua;
    return($rval, $response->code, $response->status_line, $start, $tcp_end, $finish, $contentsize, $content, $md5);
}

sub updateRRD {
    my($RRD, $t, @vals) = @_;

    if (! -e $RRD){
        return(1, "could not find ${RRD}");
    } else {
#        my($lastUpdate) = RRDs::last($RRD);
#        if (my $error = RRDs::error()){
#            return(1, "RRDs::last failed on $RRD: $error");
#        }
#
#                #when the last update should have minimally happened
#        my($difference) = (time - $config->{'STEP'} + $config->{'timeout'});
#
#                #if the last update was more recent (>) when it should have happened, skip
#        if ($lastUpdate > $difference){
#            if ($config->{'DEBUG'} >= 10){
#                notify('err', "skip $RRD lastUpdate $lastUpdate > $difference");
#            }
#            return (1, "skip $RRD lastUpdate $lastUpdate > $difference");
#        }

        my($vallist) = $t . ":" . join(':', @vals);

        RRDs::update("$RRD", "$vallist");
        if (my $error = RRDs::error()) {
            return(1, "RRDs::update - $RRD [$error] (${vallist})");
        } else {
            return(0, "OK");
        }
    }
}

sub notify {
    my($severity, $mesg, $who, $longmsg) = @_;
    if (! $who){
        $who = "";
    }
    if (! $longmsg){
        $longmsg = $mesg;
    }
    my($useverity) = uc($severity);

    my($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime(time);
    $year += 1900;
    $mon += 1;
    my($timestamp) = sprintf("%02d-%02d %02d:%02d:%02d", $mon, $mday, $hour, $min, $sec);
    my($pid) = $$;

    if ($severity eq "debug"){
        if ($config->{'DEBUG'}){
            print STDERR "${useverity}: ($timestamp): $mesg\n";
        }
    } else {
        syslog($severity, "${useverity}: $mesg");
        if ($severity eq "emerg" || $severity eq "crit"){
            if ($who ne ""){
                                my($rv, $errmsg) = &sendmail($who, $who, "$mesg (${useverity})", $longmsg)
                                    ;
                                if ($rv){
                                    syslog('crit', "CRIT: could not send email to ${who} (${errmsg})");
                                }
                            }

#
# send an snmp trap
#
#      my($trapdest) = "$config->{'snmpTrapCommunity'}\@$config->{'snmpTrapHost'}";
#      snmptrap($trapdest, enterpriseOID,
#            agent, generalID, specificID, OID, type, value,
#            [OID, type, value ...])

        }
    }
}

sub sendmail {
    my($to, $from, $subject, $msg) = @_;
    if (! $msg){
        $msg = $subject;
    }

    open MAIL,"| /usr/sbin/sendmail -t -oi" or return (1, "Couldn't pipe to sendmail: $!");

    print MAIL <<"MAIL";
To: ${to}
From: ${from}
Reply-To: ${from}
Subject: ${subject}

-------------8<----------cut here----------------8<-----------------
    ${msg}
-------------8<----------cut here----------------8<-----------------
MAIL

    close MAIL or return(1, "Couldn't close sendmail pipe: $!");
return(0, "okay");
}


sub pgrep {
	my($string) = @_;
	my(@pid) = `/bin/ps auxwww | /usr/bin/egrep "${string}"`;
	for my $l (@pid){
		chomp($l);
		my($u, $pid, $cpu, $mem, $vsz, $rss, $tt, $stat, $started, $time, @cmd) = split(/\s+/, $l);
		my($cmdstring) = join(' ', @cmd);
		next if ($cmdstring =~ /grep/);
		return($pid, $u, $cmdstring);
	}
}

1;
