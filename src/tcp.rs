// #![allow(unused)]

use bitflags::bitflags;
use nix::NixPath;

use crate::utils::{is_between_wrapped, wrapping_lt};
use std::{
    collections::{BTreeMap, VecDeque},
    io::{self, Write},
    time,
};

bitflags! {
    pub(crate) struct Available: u8 {
        const READ = 0b00000001;
        const WRITE = 0b00000010;
    }
}

// RFC 793 (page 23)
#[derive(Debug)]
pub enum State {
    // Listen,
    SynRecvd,
    Estab,
    FinWait1,
    FinWait2,
    TimeWait,
}

impl State {
    fn is_synchronized(&self) -> bool {
        match *self {
            State::SynRecvd => false,
            State::Estab | State::FinWait1 | State::TimeWait | State::FinWait2 => true,
        }
    }
}

struct Timers {
    send_times: BTreeMap<u32, time::Instant>,
    srtt: f64,
}

pub struct Connection {
    state: State,
    send: SendSequenceSpace,
    recv: RecvSequenceSpace,
    ip: etherparse::Ipv4Header,
    tcp: etherparse::TcpHeader,
    timers: Timers,

    // bytes that the Connection has read, but haven't returned to the caller
    pub(crate) incoming: VecDeque<u8>,
    // bytes that the user has given to the connection but we have not been acked by the reciever (incase a packet gets dropped)
    pub(crate) unacked: VecDeque<u8>,

    pub(crate) closed: bool,
    closed_at: Option<u32>,
}

// State of the Send Sequence Space (RFC 793 S3.2 F4)
struct SendSequenceSpace {
    // send unacknowledged
    una: u32,
    // send next
    nxt: u32,
    // send window
    wnd: u16,
    // send urgent pointer
    up: bool,
    // segment sequence number used for last window update
    wl1: usize,
    // segment acknowledgement number used for last window update
    wl2: usize,
    // initial send sequence number
    iss: u32,
}

// State of the Recv Sequence Space (RFC 793 S3.2 F5)
struct RecvSequenceSpace {
    // receive next
    nxt: u32,
    // receive window
    wnd: u16,
    // receive urgent pointer
    up: bool,
    // initial send sequence number
    irs: u32,
}

/*
Lifetimes are essentially used in the `on_packet` method to ensure that the references to the packet data (`iph`, `tcph`, and `data`) are valid for the duration of the method call.
Since the packet data is borrowed from the buffer (`buf`), which is modified in each iteration of the loop, it's essential to ensure that the references to this data are valid and do not outlive the buffer itself.
*/

impl Connection {
    pub(crate) fn is_rcv_closed(&self) -> bool {
        if let State::TimeWait = self.state {
            // TODO: any state after received FIN: CLOSE-WAIT, LAST-ACK, CLOSED, CLOSING
            true
        } else {
            false
        }
    }

    fn availability(&self) -> Available {
        // TODO: take into account self.state

        let mut a = Available::empty();
        if self.is_rcv_closed() || !self.incoming.is_empty() {
            a |= Available::READ;
        }

        // TODD: set Available::WRITE
        // if  {
        //     a |= Available::WRITE;
        // }

        a
    }

    pub fn accept<'a>(
        // 'a - Lifetime of the packet
        nic: &mut tun_tap::Iface,
        iph: etherparse::Ipv4HeaderSlice<'a>,
        tcph: etherparse::TcpHeaderSlice<'a>,
        _data: &'a [u8],
    ) -> io::Result<Option<Self>> {
        if !tcph.syn() {
            // only expected SYN packet
            return Ok(None);
        }

        let iss = 0;
        let wnd = 1024;
        let mut c = Connection {
            timers: Timers {
                send_times: Default::default(),
                srtt: time::Duration::from_secs(1 * 60).as_secs_f64(),
            },

            state: State::SynRecvd,

            send: SendSequenceSpace {
                iss,
                una: iss,
                nxt: iss,
                wnd,
                up: false,

                wl1: 0,
                wl2: 0,
            },

            recv: RecvSequenceSpace {
                irs: tcph.sequence_number(),
                nxt: tcph.sequence_number() + 1,
                wnd: tcph.window_size(),
                up: false,
            },

            // parse SYN packet and send SYN ACK
            tcp: etherparse::TcpHeader::new(tcph.destination_port(), tcph.source_port(), iss, wnd),

            ip: etherparse::Ipv4Header::new(
                0,
                64,
                etherparse::IpNumber::TCP,
                [
                    iph.destination()[0],
                    iph.destination()[1],
                    iph.destination()[2],
                    iph.destination()[3],
                ],
                [
                    iph.source()[0],
                    iph.source()[1],
                    iph.source()[2],
                    iph.source()[3],
                ],
            )
            .unwrap(),

            incoming: Default::default(),
            unacked: Default::default(),

            closed: false,
            closed_at: None,
        };

        // Establish connection
        c.tcp.syn = true;
        c.tcp.ack = true;

        c.write(nic, c.send.nxt, 0)?;
        Ok(Some(c))
    }

    fn write(&mut self, nic: &mut tun_tap::Iface, seq: u32, mut limit: usize) -> io::Result<usize> {
        let mut buf = [0u8; 1500];

        self.tcp.sequence_number = self.send.nxt;
        self.tcp.acknowledgment_number = self.recv.nxt;

        // TODO: return +1 for SYN/FIN
        println!(
            "write(ACK: {}, Seq: {}, Limit: {}) | SYN {:?} | FIN {:?}",
            self.recv.nxt - self.recv.irs,
            seq,
            limit,
            self.tcp.syn,
            self.tcp.fin,
        );

        let mut offset = seq.wrapping_sub(self.send.una) as usize;
        // we need special-case the two "virtual" bytes SYN and FIN
        if let Some(closed_at) = self.closed_at {
            if seq == closed_at.wrapping_add(1) {
                // trying to write following FIN
                offset = 0;
                limit = 0;
            }
        }
        println!(
            "using offset {} base {}: {}",
            offset,
            self.send.una,
            // self.unacked.as_slices(),
            std::str::from_utf8(self.unacked.as_slices().0).unwrap()
        );

        let (mut h, mut t) = self.unacked.as_slices();
        if h.len() >= offset {
            h = &h[offset..];
        } else {
            let skipped = h.len();
            h = &[];
            t = &t[(offset - skipped)..];
        }

        let max_data = std::cmp::min(limit, h.len() + t.len());
        let size = std::cmp::min(
            buf.len(),
            self.tcp.header_len() as usize + self.ip.header_len() as usize + max_data,
        );
        self.ip
            .set_payload_len(size - self.ip.header_len() as usize);

        /*
        When a packet is received, the recipient can recalculate the checksum using the same algorithm
        and compare it to the checksum value included in the packet.
        If the recalculated checksum matches the transmitted checksum,
        it indicates that the packet was not corrupted during transmission.
        However, if the checksum values do not match, it suggests that the packet
        may have been altered or corrupted, and the recipient can request a retransmission of the packet

        Ensures that the TCP packet can be verified for integrity when it is transmitted over the network
        */

        // unwritten is mutable slice pointer to buf
        // So, when we write into it, it removes it from the start
        // and the new writes only happen to parts that were not written yet.
        let buf_len = buf.len();
        let mut unwritten = &mut buf[..];

        self.ip.write(&mut unwritten)?;
        let ip_header_ends_at = buf_len - unwritten.len();

        // postpone writitng the tcp header because we need the payload
        // as one contiguous slice to calculate the tcp checksum
        unwritten = &mut unwritten[self.tcp.header_len() as usize..];
        let tcp_header_ends_at = buf_len - unwritten.len();

        // write out the payload
        let payload_bytes = {
            let mut written = 0;
            let mut limit = max_data;

            // write as much as possible
            let p1l = std::cmp::min(limit, h.len());
            written += unwritten.write(&h[..p1l])?;
            limit -= written;

            // write more if possible
            let p2l = std::cmp::min(limit, t.len());
            written += unwritten.write(&h[..p2l])?;
            written
        };
        let payload_ends_at = buf_len - unwritten.len();

        // Calculate the tcp checksum and write out the tcp headers
        self.tcp.checksum = self
            .tcp
            .calc_checksum_ipv4(&self.ip, &buf[tcp_header_ends_at..payload_ends_at])
            .expect("failed to compute checksum");

        let mut tcp_header_buf = &mut buf[ip_header_ends_at..tcp_header_ends_at];
        self.tcp.write(&mut tcp_header_buf);

        let mut next_seq = seq.wrapping_add(payload_bytes as u32);
        if self.tcp.syn {
            next_seq = next_seq.wrapping_add(1);
            self.tcp.syn = false;
        }
        if self.tcp.fin {
            next_seq = next_seq.wrapping_add(1);
            self.tcp.fin = false;
        }
        if wrapping_lt(self.send.nxt, next_seq) {
            self.send.nxt = next_seq;
        }

        self.timers.send_times.insert(seq, time::Instant::now());

        nic.send(&buf[..payload_ends_at])?;

        Ok(payload_bytes)
    }

    fn send_rst(&mut self, nic: &mut tun_tap::Iface) -> io::Result<()> {
        self.tcp.rst = true;

        // TODO:
        // If the incoming segment has an ACK field
        /* Reset takes its *sequence_number* from the ACK field
        otherwise, zero and the ACK field is set to
        sum of the sequence_number and segment length of the incoming segment
        Connection State remains the same
        */

        // TODO:
        // Handle synchronized RST
        /* If the connection is in a synchronized state (ESTABLISH, FIN-WAIT-1,
        FIN-WAIT-2, CLOSE-WAIT, CLOSING, LAST-ACK, TIME-WAIT), any
        unacceptable segment must elicit only an empty acknowledgement segment
        containing the current send-sequence number and an acknowledgement
        indicating the next sequence_number expected to be received, and
        the connection remains in the same state.
        */

        self.tcp.sequence_number = 0;
        self.tcp.acknowledgment_number = 0;
        self.write(nic, self.send.nxt, 0)?;

        Ok(())
    }

    pub(crate) fn on_tick(&mut self, nic: &mut tun_tap::Iface) -> io::Result<()> {
        if let State::FinWait2 | State::TimeWait = self.state {
            // we have shutdown our write side and the other side acked,
            // no need to (re)transmit anything
            return Ok(());
        }

        let nunacked_data = self
            .closed_at
            .unwrap_or(self.send.nxt)
            .wrapping_sub(self.send.una);
        let nunsent_data = self.unacked.len() as u32 - nunacked_data;

        let waited_for = self
            .timers
            .send_times
            .range(self.send.una..)
            .next()
            .map(|t| t.1.elapsed());

        let should_retransmit = if let Some(waited_for) = waited_for {
            waited_for > time::Duration::from_secs(1)
                && waited_for.as_secs_f64() > 1.5 * self.timers.srtt
        } else {
            false
        };

        if should_retransmit {
            let resend = std::cmp::min(self.unacked.len() as u32, self.send.wnd as u32);
            if resend < self.send.wnd as u32 && self.closed {
                // TODO: Include the FIN (not sure)
                self.tcp.fin = true;
                self.closed_at = Some(self.send.una.wrapping_add(self.unacked.len() as u32));
            }
            self.write(nic, self.send.una, resend as usize)?;
        } else {
            // Send new data if new data is there and the window has space
            if nunsent_data == 0 && self.closed_at.is_some() {
                return Ok(());
            }

            let allowed = self.send.wnd as u32 - nunacked_data;
            if allowed == 0 {
                return Ok(());
            }

            let send = std::cmp::min(nunsent_data, allowed);
            if send < allowed && self.closed && self.closed_at.is_none() {
                self.tcp.fin = true;
                self.closed_at = Some(self.send.una.wrapping_add(self.unacked.len() as u32));
            }

            self.write(nic, self.send.nxt, send as usize)?;
        }

        Ok(())
    }

    pub(crate) fn on_packet<'a>(
        &mut self,
        nic: &mut tun_tap::Iface,
        iph: etherparse::Ipv4HeaderSlice<'a>,
        tcph: etherparse::TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> io::Result<Available> {
        // --- Validate Sequence Numbers (RFC 793 S3.3)

        // --- Valid Segment Check
        // Okay if it acks at least one byte, so two statements are true:
        // RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
        // RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND

        let seqn = tcph.sequence_number();
        let mut slen = data.len() as u32;
        if tcph.fin() {
            slen += 1;
        };
        if tcph.syn() {
            slen += 1;
        };
        let wend = self.recv.nxt.wrapping_add(self.recv.wnd as u32);

        let okay = if slen == 0 {
            // zero-length segment has separate rules for acceptance
            if self.recv.wnd == 0 {
                if seqn != self.recv.nxt {
                    false
                } else {
                    true
                }
            } else if !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn, wend) {
                false
            } else {
                true
            }
        } else {
            if self.recv.wnd == 0 {
                false
            } else if !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn, wend)
                && !is_between_wrapped(
                    self.recv.nxt.wrapping_sub(1),
                    seqn.wrapping_add(slen - 1),
                    wend,
                )
            {
                false
            } else {
                true
            }
        };

        if !okay {
            eprintln!("NOT OKAY");
            self.write(nic, self.send.nxt, 0)?;
            return Ok(self.availability());
        }

        // If the ACK bit if off, drop the segment and return
        if !tcph.ack() {
            if tcph.syn() {
                // got SYN part of initial handshake
                assert!(data.is_empty());
                self.recv.nxt = seqn.wrapping_add(1);
            }
            eprintln!("No ACK");
            return Ok(self.availability());
        }

        let ackn = tcph.acknowledgment_number();
        if let State::SynRecvd = self.state {
            // --- If Acceptable ACK Check passes
            // then enter ESTABLISHED state and continue processing
            if is_between_wrapped(
                self.send.una.wrapping_sub(1),
                ackn,
                self.send.nxt.wrapping_add(1),
            ) {
                // must have ACKed our SYN, since we detected atleast one acked byte,
                // and we have only sent one byte (SYN)
                self.state = State::Estab;
            } else {
                // TODO: <SEQ=GEG.ACK><CTL=RST>
            }
        }

        // RFC 793, Page 71
        if let State::Estab | State::FinWait1 | State::FinWait2 = self.state {
            // When ACK is between them, then only update UNA (things that haven't been acknowledged)

            if is_between_wrapped(self.send.una, ackn, self.send.nxt.wrapping_add(1)) {
                // println!(
                //     "ack for {} (last: {}); prune in {:?}",
                //     ackn, self.send.una, self.unacked
                // );
                println!(
                    "ack for {} (last: {}); prune in: {}",
                    ackn,
                    self.send.una,
                    std::str::from_utf8(self.unacked.as_slices().0).unwrap()
                );

                // TODO: if unacked empty and waiting flush, notify
                if !self.unacked.is_empty() {
                    let data_start = if self.send.una == self.send.iss {
                        // send.una hasn't been updated yet with ACK for our SYN,
                        // so data starts just beyond it
                        self.send.una.wrapping_add(1)
                    } else {
                        self.send.una
                    };

                    let acked_data_end =
                        std::cmp::min(ackn.wrapping_sub(data_start) as usize, self.unacked.len());
                    self.unacked.drain(..acked_data_end);

                    let old = std::mem::replace(&mut self.timers.send_times, BTreeMap::new());

                    let una = self.send.una;
                    let mut srtt = &mut self.timers.srtt;
                    self.timers
                        .send_times
                        .extend(old.into_iter().filter_map(|(seq, sent)| {
                            if is_between_wrapped(una, seq, ackn) {
                                *srtt = 0.8 * *srtt + (1.0 - 0.8) * sent.elapsed().as_secs_f64();
                                None
                            } else {
                                Some((seq, sent))
                            }
                        }));
                }

                // eprintln!("BAD ACK, updating UNA");
                self.send.una = ackn;
            }

            // TODO: update window

            // Shutdown the connection immediately (only for testing)
            // if let State::Estab = self.state {
            //     self.tcp.fin = true;
            //     self.write(nic, &[])?;
            //     self.state = State::FinWait2;
            // }
        }

        // RFC 793, Page 72
        if let State::FinWait1 = self.state {
            if let Some(closed_at) = self.closed_at {
                if self.send.una == closed_at.wrapping_add(1) {
                    // our FIN has been ACKed
                    self.state = State::FinWait2;
                }
            }
        }

        // RFC 793 (page 73)
        if !data.is_empty() {
            if let State::Estab | State::FinWait1 | State::FinWait2 = self.state {
                let mut unacked_data_at = self.recv.nxt.wrapping_sub(seqn) as usize;
                if unacked_data_at > data.len() {
                    // we must have reache a retransmitted FIN, that was already seen
                    // nxt points to beyond the fin, but the fun is not in data!
                    assert_eq!(unacked_data_at, data.len() + 1);
                    unacked_data_at = 0;
                }

                // Accept data and make it available to read calls
                // TODO: only read data we haven't read
                self.incoming.extend(&data[unacked_data_at..]);

                // Once the TCP takes responsibility for the data it advances
                // RCV.NXT over the data accepted, and adjusts RCV.WND as
                // appropriate to the current buffer availability. The total of
                // RCV.NXT and RCV.WND should not be reduced.
                self.recv.nxt = seqn
                    .wrapping_add(data.len() as u32)
                    .wrapping_add(if tcph.fin() { 1 } else { 0 });

                // Send an acknowledgement of the form:
                // <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK> (already handeled in write)
                self.write(nic, self.send.nxt, 0)?;
            }
        }

        if tcph.fin() {
            match self.state {
                State::FinWait2 => {
                    // done with the connection
                    println!("in state FinWait2");

                    self.recv.nxt = self.recv.nxt.wrapping_add(1);
                    self.write(nic, self.send.nxt, 0)?;
                    self.state = State::TimeWait;
                }
                _ => unreachable!(),
            }
        }

        Ok(self.availability())
    }

    pub(crate) fn close(&mut self) -> io::Result<()> {
        self.closed = true;
        match self.state {
            State::Estab | State::SynRecvd => {
                self.state = State::FinWait1;
            }

            State::FinWait1 | State::FinWait2 => {}

            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "connection already closed",
                ))
            }
        };

        Ok(())
    }

    pub(crate) fn wake_up(&mut self) -> io::Result<()> {
        self.closed = true;

        Ok(())
    }
}
