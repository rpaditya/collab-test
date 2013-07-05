#!/usr/bin/env perl

use strict;
use warnings;

# PODNAME:  ldapd.pl
# ABSTRACT: Script to invoke the LDAP server.

# VERSION

use Net::LDAP::SimpleServer;

# passing a specific configuration file
my $server = Net::LDAP::SimpleServer->new({
    conf_file => 'ldapd.conf'
});
 
# make it spin with options
$server->run({ allow_anon => 1 });
