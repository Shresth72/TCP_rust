#!/bin/bash 

# cargo build
cargo b --release

# Exit status of last command exec
ext=$?

# Exit script on fail
if [[ $ext -ne 0 ]]; then
    exit $ext
fi

# Allow exec to perform network configuration tasks
sudo setcap cap_net_admin=eip target/release/tcp_rust
target/release/tcp_rust &

# Assign subnet to tun0 process 
sudo ip addr add 192.168.0.1/24 dev tun0
# Activate Network Interface tun0
sudo ip link set up dev tun0

# Process ID of last bg process 
pid=$!

# Catch SIGINT (Ctrl C) or SIGTERM signals
trap "kill $pid" INT TERM
wait $pid

