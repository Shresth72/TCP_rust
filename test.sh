#!/bin/bash 

# Find running processes
ps -ef 

# Kill process 
kill $pid

# Watch the received bytes on tun0 
tshark -i tun0

# Send IPv4 Ping Packets to tun0
ping -I tun0 192.168.0.2

# Send IPv4 TCP Packets to tun0 (port: 8000)
nc 192.168.0.2 8000

# Send http curl requests (port: 8000)
curl 192.168.0.2:8000
