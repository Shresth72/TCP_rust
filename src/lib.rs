#![allow(unused)]

mod tcp;
mod utils;

use utils::Quad;

use std::{
    cmp::min,
    collections::{HashMap, VecDeque},
    io::{self, prelude::*},
    net::Shutdown,
    sync::{Arc, Mutex},
    thread,
};

const SENDQUEUE_SIZE: usize = 1024;

type InterfaceHandle = Arc<Mutex<ConnectionManager>>;

pub struct Interface {
    ih: InterfaceHandle,
    jh: thread::JoinHandle<io::Result<()>>,
}

impl Drop for Interface {
    fn drop(&mut self) {
        todo!()
    }
}

#[derive(Default)]
struct ConnectionManager {
    connections: HashMap<Quad, tcp::Connection>,
    pending: HashMap<u16, VecDeque<Quad>>,
}

fn packet_loop(mut nic: tun_tap::Iface, ih: InterfaceHandle) -> io::Result<()> {
    let mut buf = [0u8; 1504];

    loop {
        let nbytes = nic.recv(&mut buf[..])?;

        /*
        if s/without_packet_info/new/:

        let _eth_flags = u16::from_be_bytes([buf[0], buf[1]]);
        let eth_protocol = u16::from_be_bytes([buf[2], buf[3]]);
        if eth_protocol != 0x0800 {
            // Not IPv4 (Avoids receiving packet from the default network or Internet Provider)
            continue;
        }

        and also include on send
        */

        match etherparse::Ipv4HeaderSlice::from_slice(&buf[..nbytes]) {
            Ok(iph) => {
                let src = iph.source_addr();
                let dst = iph.destination_addr();
                if iph.protocol() != etherparse::IpNumber(0x06) {
                    // eprintln!("Not a TCP Packet");
                    continue;
                }

                // TCP Packet Parsing
                match etherparse::TcpHeaderSlice::from_slice(&buf[iph.slice().len()..nbytes]) {
                    Ok(tcph) => {
                        use std::collections::hash_map::Entry;

                        // payload begins after the prvs headers and the tcp headers
                        let datai = iph.slice().len() + tcph.slice().len();

                        // Deref to get the underlying attributes as it's a MutexGuard
                        let mut cm = ih.lock().unwrap();
                        let mut cm = &mut *cm;

                        let q = Quad {
                            src: (src, tcph.source_port()),
                            dst: (dst, tcph.destination_port()),
                        };

                        match cm.connections.entry(q) {
                            Entry::Occupied(mut c) => {
                                c.get_mut()
                                    .on_packet(&mut nic, iph, tcph, &buf[datai..nbytes])?;
                            }

                            // If there is no current Connection
                            // AND we are willing to create a Connection
                            Entry::Vacant(e) => {
                                if let Some(pending) = cm.pending.get_mut(&tcph.destination_port())
                                {
                                    if let Some(c) = tcp::Connection::accept(
                                        &mut nic,
                                        iph,
                                        tcph,
                                        &buf[datai..nbytes],
                                    )? {
                                        e.insert(c);
                                        pending.push_back(q);

                                        // TODO: wake up pending accept()
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("ignoring bad tcp packet {:?}", e);
                    }
                }
            }
            Err(_) => {
                // eprintln!("ignoring packet {:?}", e);
            }
        }
    }
}

impl Interface {
    pub fn new() -> io::Result<Self> {
        let nic = tun_tap::Iface::without_packet_info("tun0", tun_tap::Mode::Tun)?;
        let ih: InterfaceHandle = Arc::default();

        // Threads to manage the nic and only it has access to nic
        let jh = {
            let ih = ih.clone();
            thread::spawn(move || {
                // Handle connections like main
                packet_loop(nic, ih)
            })
        };

        Ok(Interface { ih, jh })
    }

    pub fn bind(&mut self, port: u16) -> io::Result<TcpListener> {
        use std::collections::hash_map::Entry;

        let mut cm = self.ih.lock().unwrap();

        // Do something to start accepting SYN packets on port
        match cm.pending.entry(port) {
            Entry::Vacant(v) => v.insert(VecDeque::new()),
            Entry::Occupied(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "port already bound",
                ))
            }
        };

        drop(cm);
        Ok(TcpListener(port, self.ih.clone()))
    }
}

pub struct TcpListener(u16, InterfaceHandle);

impl Drop for TcpListener {
    fn drop(&mut self) {
        todo!()
    }
}

impl TcpListener {
    pub fn accept(&mut self) -> io::Result<TcpStream> {
        let mut cm = self.1.lock().unwrap();
        if let Some(quad) = cm
            .pending
            .get_mut(&self.0)
            .expect("port closed while listening still active")
            .pop_front()
        {
            return Ok(TcpStream(quad, self.1.clone()));
        } else {
            // TODO: block
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "no conection available to accept",
            ));
        }
    }
}

pub struct TcpStream(Quad, InterfaceHandle);

impl Drop for TcpStream {
    fn drop(&mut self) {
        todo!()
    }
}
impl Read for TcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut cm = self.1.lock().unwrap();

        // Lookup the connection for the TCP we're trying to read from
        let c = cm.connections.get_mut(&self.0).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "stream was terminated unexpectedly",
            )
        })?;

        // If no data, block the current read thread
        if c.incoming.is_empty() {
            // TODO: block
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "no bytes to read",
            ));
        }

        // TODO: detect FIN and return nread = 0

        // Read as much data as possible from the incoming buf
        let mut nread = 0;
        let (head, tail) = c.incoming.as_slices();

        let hread = min(buf.len(), head.len());
        buf.copy_from_slice(&head[..hread]);
        nread += hread;

        let tread = min(buf.len() - nread, tail.len());
        buf.copy_from_slice(&tail[..tread]);
        nread += tread;

        drop(c.incoming.drain(..nread));
        Ok(nread)
    }
}

impl Write for TcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut cm = self.1.lock().unwrap();

        let c = cm.connections.get_mut(&self.0).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "stream was terminated unexpectedly",
            )
        })?;

        if c.unacked.len() >= SENDQUEUE_SIZE {
            // TODO: block
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "too many bytes buffered",
            ));
        }

        // Either write the amount of bytes we have, or how much we are allowed to
        let nwrite = min(buf.len(), SENDQUEUE_SIZE - c.unacked.len());
        c.unacked.extend(buf[..nwrite].iter());

        // TODO: wake up writer

        Ok(nwrite)
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut cm = self.1.lock().unwrap();

        let c = cm.connections.get_mut(&self.0).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "stream was terminated unexpectedly",
            )
        })?;

        if c.unacked.is_empty() {
            Ok(())
        } else {
            // TODO: block
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "unacknowledged bytes",
            ));
        }
    }
}

impl TcpStream {
    pub fn shutdown(&self, _how: Shutdown) -> io::Result<()> {
        todo!()
    }
}
