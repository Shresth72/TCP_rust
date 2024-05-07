#![allow(unused)]

use std::{
    io::{self, Write},
    mem::swap,
};

pub enum State {
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
    pub fn accept<'a>(
        // 'a - Lifetime of the packet
        nic: &mut tun_tap::Iface,
        iph: etherparse::Ipv4HeaderSlice<'a>,
        tcph: etherparse::TcpHeaderSlice<'a>,
        _data: &'a [u8],
    ) -> io::Result<Option<Self>> {
        let mut buf = [0u8; 1500];

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

        self.tcp.checksum = self
            .tcp
            .calc_checksum_ipv4(&self.ip, &[])
            .expect("failed to compute checksum");

        // Write out the headers (segment)
        use std::io::Write;

        // unwritten is mutable slice pointer to buf
        // So, when we write into it, it removes it from the start
        // and the new writes only happen to parts that were not written yet.
        let mut unwritten = &mut buf[..];
        self.ip.write(&mut unwritten);
        self.tcp.write(&mut unwritten);
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

    pub fn on_packet<'a>(
        &mut self,
        nic: &mut tun_tap::Iface,
        iph: etherparse::Ipv4HeaderSlice<'a>,
        tcph: etherparse::TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> io::Result<()> {
        // --- Validate Sequence Numbers (RFC 793 S3.3)

        // --- Valid Segment Check
        // Okay if it acks at least one byte, so two statements are true:
        // RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
        // RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
        let seqn = tcph.sequence_number();
        let wend = self.recv.nxt.wrapping_add(self.recv.wnd as u32);
        let slen = match data.len() as u32 {
            len if tcph.fin() && tcph.syn() => len + 2,
            len if tcph.fin() || tcph.syn() => len + 1,
            len => len,
        };

        let okay = if slen == 0 {
            // zero length segment has seperate rules for acceptance
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
            self.write(nic, &[])?;
            return Ok(());
        }

        // When the reciever accepts a segment, it advances the RCV NXT and sends an ACK
        self.recv.nxt = seqn.wrapping_add(slen);
        // TODO: if not_acceptable, send ACK
        // <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>

        // If the ACK bit if off, drop the segment and return
        if !tcph.ack() {
            return Ok(());
        }

        let ackn = tcph.acknowledgment_number();
        if let State::SynRecvd = self.state {
            /// --- If Acceptable ACK Check passes
            /// then enter ESTABLISHED state and continue processing
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
                return Ok(());
            }
            self.send.una = ackn;

            assert!(data.is_empty());

            if let State::Estab = self.state {
                // Terminate the connection (test)
                // simplex CLOSE - may continue to receive but won't send back
                // TODO: needs to be stored in the Retransmission queue
                // as fin should only be set at the very last set of packet sent during the connection
                self.tcp.fin = true;
                self.write(nic, &[])?;
                self.state = State::FinWait1;
            }
        }

        // RFC 793, Page 72
        if let State::FinWait1 = self.state {
            if self.send.una == self.send.iss + 2 {
                // our FIN has been ACKed
                self.state = State::FinWait2;
            }
        }

        if tcph.fin() {
            match self.state {
                State::FinWait2 => {
                    // we're done with the connection
                    self.write(nic, &[])?;
                    self.state = State::TimeWait;
                }
                _ => unreachable!(),
            }
        }

        Ok(())
    }
}

fn is_between_wrapped(start: u32, x: u32, end: u32) -> bool {
    use std::cmp::Ordering;

    match start.cmp(&x) {
        Ordering::Equal => return false,
        Ordering::Less => {
            // check is violated if NXT is between UNA and ACK
            if end >= start && end <= x {
                return false;
            }
        }
        Ordering::Greater => {
            // check is ok if NXT is between UNA and ACK
            if end > x && end < start {
            } else {
                return false;
            }
        }
    }

    true
}
