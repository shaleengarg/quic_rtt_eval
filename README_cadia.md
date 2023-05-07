The following steps are given Cadia RTT evaluation

Make a topology with 3 boxes (B1, B2, B3). B2 is connected to both B1 and B3. B1 and B3 traffic for each other flows through B2.

Case 1
1.	Configure B2 to reorder packets from B3 to B1
tc qdisc add dev enp9s4f1 root netem reorder 100 gap 5 delay 1 ms
 < enp9s4f1> is interface connecting B2 to B1
2.	Configure tcpProbe tracepoint on client to get the dump for traffic
echo 1 > /sys/kernel/debug/tracing/events/tcp/tcp_probe/enable
3.	Start the server script server.py on B3
4.	Start packet captures on all 3 boxes. Note: On middle box add an extra filter to capture only packets destined to server. This capture will be fed to LB algorithm
5.	Start the client script client.py on B1
6.	Get tcpProbe output for client 
a.	cat /sys/kernel/debug/tracing/trace | grep dest=ip:port > file
7.	Run the parseInput.py on file obtained on step 6
8.	Run the parseClient.py with client side packet capture
a.	python3 parseClient.py --inputFile /users/bvs17/ testc.pcap
9.	Run the parseLB.py with middle box packet capture
a.	python3 parseLB.py --fwdFile /users/bvs17/forward.pcap --srcIP <clientIP> --srcPort <clientPort> --dstIP <serverIP> --dstPort <serverPort>
10.	Compare the results

Case 2
1.	Configure B2 to drop packets from B1 to B3
tc qdisc add dev <interface> root netem loss 0.1%
<interface> connecting B3 to B2
2.	Configure tcpProbe tracepoint on client to get the dump for traffic
echo 1 > /sys/kernel/debug/tracing/events/tcp/tcp_probe/enable
3.	Start the server script server.py on B3
4.	Start packet captures on all 3 boxes. Note: On middle box add an extra filter to capture only packets destined to server. This capture will be fed to LB algorithm
5.	Start the client script client.py on B1
6.	Get tcpProbe output for client 
a.	cat /sys/kernel/debug/tracing/trace | grep dest=ip:port > file
7.	Run the parseInput.py on file obtained on step 6
8.	Run the parseClient.py with client side packet capture
a.	python3 parseClient.py --inputFile /users/bvs17/ testc.pcap
9.	Run the parseLB.py with middle box packet capture
a.	python3 parseLB.py --fwdFile /users/bvs17/forward.pcap --srcIP <clientIP> --srcPort <clientPort> --dstIP <serverIP> --dstPort <serverPort>
10.	Compare the results

Case 3:
1.	Run the parseCaida.py script on forward and reverse direction packet trace 
2.	Run generateGroundTruth.py 
3.	Run parseLbCaida.py file on forward traffic as in Case 2 Step 9
4.	Compare the results 

