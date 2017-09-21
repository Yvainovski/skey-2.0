
msg=`echo foobar | ./skey-2.0/bin/key 88 ka9q2 | tail -1`
echo 'Testing key 88 ka9q2 with "WORN MUD CORK DARK MONT HAP".....'

if [ "$msg" != "WORN MUD CORK DARK MONT HAP" ] ; then
	echo 'Test Failed! Your output is:'
	echo  "$msg"
        exit 1
else
        exit 0
fi