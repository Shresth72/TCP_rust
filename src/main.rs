use std::io;

fn main() -> io::Result<()> {
    let nic = tun_tap::Iface::new("tun0", tun_tap::Mode::Tun)?;
    let mut buf = [0u8; 1504];

    loop {
        let nbytes = nic.recv(&mut buf[..])?;
        let _eth_flags = u16::from_be_bytes([buf[0], buf[1]]);
        let eth_protocol = u16::from_be_bytes([buf[2], buf[3]]);
        if eth_protocol != 0x0800 {
            // Not IPv4 (Also avoid receiving packet from the default network or Internet Provider)
            continue;
        }

        match etherparse::Ipv4HeaderSlice::from_slice(&buf[4..nbytes]) {
            Ok(packet) => {
                let src = packet.source_addr();
                let dst = packet.destination_addr();
                let proto = packet.protocol();
                if proto != etherparse::IpNumber(0x06) {
                    // eprintln!("Not a TCP Packet");
                    continue;
                }

                // TCP Packet Parsing
                match etherparse::TcpHeaderSlice::from_slice(&buf[4 + packet.slice().len()..]) {
                    Ok(p) => {
                        eprintln!(
                            "{} -> {} {:?} bytes of tcp to port: {:?}",
                            src,
                            dst,
                            p.slice().len(),
                            p.destination_port()
                        );
                    }
                    Err(e) => {
                        eprintln!("ignoring bad tcp packet {:?}", e);
                    }
                }
            }
            Err(e) => {
                eprintln!("ignoring packet {:?}", e);
            }
        }
    }
}
