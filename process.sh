#!/bin/bash 

# Find running processes
ps -ef 

# Kill process 
kill $pid

# Ping some address on the subnet (sending ping packets)
ping -I tun0 192.168.0.2

# Watch the received bytes on tun0 
tshark -i tun0
