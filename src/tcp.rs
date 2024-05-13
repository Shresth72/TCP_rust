#![allow(unused)]

use bitflags::bitflags;
use nix::NixPath;

use crate::utils::is_between_wrapped;
use std::{
    collections::VecDeque,
    io::{self, Write},
};

bitflags! {
    pub(crate) struct Available: u8 {
        const READ = 0b00000001;
        const WRITE = 0b00000010;
    }
}

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

pub struct Connection {
    state: State,
    send: SendSequenceSpace,
    recv: RecvSequenceSpace,
    ip: etherparse::Ipv4Header,
    tcp: etherparse::TcpHeader,

    // bytes that the Connection has read, but haven't returned to the caller
    pub(crate) incoming: VecDeque<u8>,
    // bytes that the user has given to the connection but we have not been acked by the reciever (incase a packet gets dropped)
    pub(crate) unacked: VecDeque<u8>,
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
        };

        // Establish connection
        c.tcp.syn = true;
        c.tcp.ack = true;

        c.write(nic, &[])?;
        Ok(Some(c))
    }

    fn write(&mut self, nic: &mut tun_tap::Iface, payload: &[u8]) -> io::Result<usize> {
        let mut buf = [0u8; 1500];

        self.tcp.sequence_number = self.send.nxt;
        self.tcp.acknowledgment_number = self.recv.nxt;

        let size = std::cmp::min(
            buf.len(),
            self.tcp.header_len() as usize + self.ip.header_len() as usize + payload.len(),
        );
        let _ = self
            .ip
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

        self.tcp.checksum = self
            .tcp
            .calc_checksum_ipv4(&self.ip, &[])
            .expect("failed to compute checksum");

        // Write out the headers (segment)

        // unwritten is mutable slice pointer to buf
        // So, when we write into it, it removes it from the start
        // and the new writes only happen to parts that were not written yet.
        let mut unwritten = &mut buf[..];
        self.ip.write(&mut unwritten)?;
        self.tcp.write(&mut unwritten)?;

        let payload_bytes = unwritten.write(payload)?;
        let unwritten = unwritten.len();

        // When the sender creates a segment and transmits it
        // the sender advances SND NXT
        self.send.nxt = self.send.nxt.wrapping_add(payload_bytes as u32);
        if self.tcp.syn {
            self.send.nxt = self.send.nxt.wrapping_add(1);
            self.tcp.syn = false;
        }
        if self.tcp.fin {
            self.send.nxt = self.send.nxt.wrapping_add(1);
            self.tcp.fin = false;
        }

        nic.send(&buf[..buf.len() - unwritten])?;
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
        self.write(nic, &[])?;

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
            self.write(nic, &[])?;
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
            if !is_between_wrapped(self.send.una, ackn, self.send.nxt.wrapping_add(1)) {
                // When ACK is between them, then only update UNA (things that haven't been acknowledged)
                eprintln!("BAD ACK, updating UNA");
                self.send.una = ackn;
            }

            // TODO: prune self.unacked
            // TODO: if unacked empty and waiting flush, notify
            // TODO: update window

            // Shutdown the connection immediately (only for testing)
            if let State::Estab = self.state {
                // TODO: needs to be stored in the retransmission queue!

                self.tcp.fin = true;
                self.write(nic, &[])?;
                self.state = State::FinWait2;
            }
        }

        // RFC 793, Page 72
        if let State::FinWait1 = self.state {
            if self.send.una == self.send.iss + 2 {
                // our FIN has been ACKed
                self.state = State::FinWait2;
            }
        }

        // RFC 793 (page 73)
        // if !data.is_empty() {
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
            self.write(nic, &[])?;
        }
        // }

        if tcph.fin() {
            match self.state {
                State::FinWait2 => {
                    println!("Finwait2");
                    self.write(nic, &[])?;
                    self.state = State::TimeWait;
                }

                State::FinWait1 => {
                    println!("Finwait1");
                }
                _ => unreachable!(),
            }

            // if let State::FinWait2 = self.state {
            //     // we're done with the connection
            //     self.recv.nxt = self.recv.nxt.wrapping_add(1);
            //     self.write(nic, &[])?;
            //     self.state = State::TimeWait;
            // }
        }

        Ok(self.availability())
    }
}
