collab-test
===========

under t/ - collaboration technology testing tools

for now we focus on SIP and ENUM

same License as perl Net-SIP, ie.:

http://search.cpan.org/~sullr/Net-SIP-0.62_12/

the RRDs we produce are most easily viewed in a dashboard like that
produced by drraw <http://web.taranis.org/drraw/>, for example:

https://test-http.ilab.umnet.umich.edu/drraw/drraw.cgi?Mode=view;Dashboard=1364007517.43683

where the red line shows the SIP call status, the black line the
received RTP kbytes/10 (to scale correctly and fit on that graph) and
the stacked area yellow is the DNS lookup time, and the aqua is the
total call time

under ldap/ - simple to use LDAP testing server for SIP clients/video
endpoints, useful to test different schemas trivially and control size of
directory
