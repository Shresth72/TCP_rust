#!/bin/bash 

cargo b --release

# don't run if compilation fails
ext=$?
if [[ $ext -ne 0 ]]; then
    exit $ext
fi

sudo ip addr add 192.168.0.1/24 dev tun0
sudo ip link set up dev tun0
sudo setcap cap_net_admin=eip target/release/tcp_rust
target/release/tcp_rust &

# keeping the process id
pid=$!

trap "kill $pid" INT TERM

wait $pid

