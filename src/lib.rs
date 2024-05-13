#![allow(unused)]

mod tcp;
mod utils;

use utils::Quad;

use std::{
    cmp::min,
    collections::{HashMap, VecDeque},
    io::{self, prelude::*},
    net::Shutdown,
    sync::{Arc, Condvar, Mutex},
    thread,
};

const SENDQUEUE_SIZE: usize = 1024;

#[derive(Default)]
struct CondMutex {
    manager: Mutex<ConnectionManager>,
    pending_var: Condvar,
    rcv_var: Condvar,
}

type InterfaceHandle = Arc<CondMutex>;

pub struct Interface {
    ih: Option<InterfaceHandle>,
    jh: Option<thread::JoinHandle<io::Result<()>>>,
}

impl Drop for Interface {
    // Cannot drop ih lock, as JoinHandle consumes self
    // So, Interface should be an Option<>
    fn drop(&mut self) {
        // When Interface drops, all the connections drop too
        self.ih.as_mut().unwrap().manager.lock().unwrap().terminate = true;

        drop(self.ih.take());
        self.jh
            .take()
            .expect("interface dropped more than once")
            .join()
            .unwrap()
            .unwrap();

        eprintln!("drop from Interface");
    }
}

#[derive(Default)]
struct ConnectionManager {
    terminate: bool,
    connections: HashMap<Quad, tcp::Connection>,
    pending: HashMap<u16, VecDeque<Quad>>,
}

fn packet_loop(mut nic: tun_tap::Iface, ih: InterfaceHandle) -> io::Result<()> {
    let mut buf = [0u8; 1504];

    loop {
        // TODO: set a timeout for this recv for TCP timers or ConnectionManager::terminate
        let nbytes = nic.recv(&mut buf[..])?;

        // TODO: if self.terminate && Arc::get_strong_refs(ih) == 1;
        // then tear down all connections

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
                        let mut cmg = ih.manager.lock().unwrap();
                        let mut cm = &mut *cmg;

                        let q = Quad {
                            src: (src, tcph.source_port()),
                            dst: (dst, tcph.destination_port()),
                        };

                        match cm.connections.entry(q) {
                            Entry::Occupied(mut c) => {
                                eprintln!("Got packet for known quad {:?}", q);
                                let a = c.get_mut().on_packet(
                                    &mut nic,
                                    iph,
                                    tcph,
                                    &buf[datai..nbytes],
                                )?;

                                // TODO: compare before/after
                                drop(cmg);
                                if a.contains(tcp::Available::READ) {
                                    ih.rcv_var.notify_all();
                                }

                                if a.contains(tcp::Available::WRITE) {
                                    // TODO: ih.send_var.notify_all();
                                }
                            }

                            // If there is no current Connection
                            // AND we are willing to create a Connection
                            Entry::Vacant(e) => {
                                eprintln!("Got packet for unknown quad {:?}", q);
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

                                        // When it notices a pending packet
                                        // Release the lock from the current thread &
                                        // Notify the threads
                                        drop(cmg);
                                        ih.pending_var.notify_all();

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

        Ok(Interface {
            ih: Some(ih),
            jh: Some(jh),
        })
    }

    pub fn bind(&mut self, port: u16) -> io::Result<TcpListener> {
        use std::collections::hash_map::Entry;

        let mut cm = self.ih.as_mut().unwrap().manager.lock().unwrap();

        // Do something to start accepting SYN packets on port
        match cm.pending.entry(port) {
            Entry::Vacant(v) => {
                v.insert(VecDeque::new());
            }
            Entry::Occupied(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "port already bound",
                ))
            }
        };

        drop(cm);
        Ok(TcpListener {
            port,
            ih: self.ih.as_mut().unwrap().clone(),
        })
    }
}

pub struct TcpListener {
    port: u16,
    ih: InterfaceHandle,
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        let mut cm = self.ih.manager.lock().unwrap();
        let pending = cm
            .pending
            .remove(&self.port)
            .expect("port closed while listening still active");

        eprintln!("drop from TcpListener");
        // terminate the dropped connections
        for quad in pending {
            todo!()
        }
    }
}

impl TcpListener {
    pub fn accept(&mut self) -> io::Result<TcpStream> {
        let mut cm = self.ih.manager.lock().unwrap();

        loop {
            if let Some(quad) = cm
                .pending
                .get_mut(&self.port)
                .expect("port closed while listening still active")
                .pop_front()
            {
                return Ok(TcpStream(quad, self.ih.clone()));
            }
            // -- Implementing Conditional Variables
            // Condvar represent rhe ability to block the thread such that it
            // Consumes no CPU time while waiting for an event to occur.
            // It takes a Mutex Lock, check a bool Predicate
            // If not true, waits on the Condvar
            // That some other thread can notify when it changes

            // We are implementing one CondVar for all pending threads

            cm = self.ih.pending_var.wait(cm).unwrap();
        }
    }
}

pub struct TcpStream(Quad, InterfaceHandle);

impl Drop for TcpStream {
    fn drop(&mut self) {
        let mut cm = self.1.manager.lock().unwrap();
        // TODO: send FIN on cm.connections[quad]
        // TODO: _eventually_ remove self.quad from cm.connections

        eprintln!("dropping the connection from TcpStream");
    }
}
impl Read for TcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut cm = self.1.manager.lock().unwrap();

        loop {
            // Lookup the connection for the TCP we're trying to read from
            let c = cm.connections.get_mut(&self.0).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "stream was terminated unexpectedly",
                )
            })?;

            eprintln!("trying to read");
            if c.is_rcv_closed() && c.incoming.is_empty() {
                // No more data to read, as we received closed (FIN)
                eprintln!("connection closed");
                return Ok(0);
            }
            eprintln!("connection still active");

            if !c.incoming.is_empty() {
                // TODO: detect FIN and return nread = 0

                // Read as much data as possible from the incoming buf
                let mut nread = 0;
                let (head, tail) = c.incoming.as_slices();
                let hread = std::cmp::min(buf.len(), head.len());
                buf[..hread].copy_from_slice(&head[..hread]);
                nread += hread;
                let tread = std::cmp::min(buf.len() - nread, tail.len());
                buf[hread..(hread + tread)].copy_from_slice(&tail[..tread]);
                nread += tread;
                drop(c.incoming.drain(..nread));
                return Ok(nread);
            }

            // If no data, block the current read thread and wait for Condvar
            cm = self.1.rcv_var.wait(cm).unwrap();
        }
    }
}

impl Write for TcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut cm = self.1.manager.lock().unwrap();

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
        let mut cm = self.1.manager.lock().unwrap();

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
        // TODO: send FIN on cm.connections[quad]
        todo!()
    }
}
