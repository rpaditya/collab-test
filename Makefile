#
# example invocation of the enum-enabled SIP robo-caller
#

VOIPDIR=${HOME}/collab-test/t
TMPDIR=/tmp
enum-test-calls:
	@${VOIPDIR}/check_enum.pl -v 6 -O ${TMPDIR}/foo.rtp -T 5 -n +99999213

