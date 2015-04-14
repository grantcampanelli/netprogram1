#!/bin/bash
make clean
make all
./trace trace_files/largeMix.pcap > test.largeMix.out
./trace trace_files/largeMix2.pcap > test.largeMix2.out
./trace trace_files/PingTest.pcap > test.ping.out
./trace trace_files/ArpTest.pcap > test.arp.out
./trace trace_files/IP_bad_checksum.pcap > test.ipbadcheck.out
./trace trace_files/smallTCP.pcap > test.smalltcp.out
./trace trace_files/TCP_bad_checksum.pcap > test.tcpbadcheck.out
./trace trace_files/UDPfile.pcap > test.udp.out


echo "******* LargeMix"
-- diff test.largeMix.out trace_files/largeMix.out.txt -y
echo "******* LargeMix2"
-- diff test.largeMix2.out trace_files/largeMix2.out.txt -y
echo "******* PingTest"
diff test.ping.out trace_files/PingTest.out.txt
echo "******* ArpTest"
-- diff test.arp.out trace_files/ArpTest.out.txt -y
echo "******* BadCheckSum"
diff test.ipbadcheck.out trace_files/IP_bad_checksum.out.txt
echo "******* Small TCP"
-- diff test.smalltcp.out trace_files/smallTCP.out.txt -y
echo "******* TCPBadCheckSum"
-- diff test.tcpbadcheck.out trace_files/TCP_bad_checksum.out.txt -y
echo "******* TCPUDPFile"
-- diff test.udp.out trace_files/UDPfile.out.txt -y