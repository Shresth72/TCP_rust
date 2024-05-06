#![allow(unused)]

use std::{io, mem::swap, usize};

pub enum State {
    SynRecvd,
    Estab,
}

pub struct Connection {
    state: State,
    send: SendSequenceSpace,
    recv: RecvSequenceSpace,
    ip: etherparse::Ipv4Header,
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
        let mut c = Connection {
            state: State::SynRecvd,
            send: SendSequenceSpace {
                iss,
                una: iss,
                nxt: iss + 1,
                wnd: 10,
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

        // parse SYN packet and send SYN ACK
        // and establish a connection
        let mut syn_ack = etherparse::TcpHeader::new(
            tcph.destination_port(),
            tcph.source_port(),
            c.send.iss,
            c.send.wnd,
        );

        // Next byte we are expecting
        syn_ack.acknowledgment_number = c.recv.nxt;
        syn_ack.syn = true;
        syn_ack.ack = true;
        let _ = c.ip.set_payload_len(syn_ack.header_len() as usize + 0);

        // The kernel already does this for tun0
        // syn_ack.checksum = syn_ack
        //    .calc_checksum_ipv4(&c.ip, &[])
        //    .expect("failed to compute checksum");

        // Write out the headers
        let unwritten = {
            let mut unwritten = &mut buf[..];
            let _ = c.ip.write(&mut unwritten);
            let _ = syn_ack.write(&mut unwritten);
            unwritten.len()
        };

        // eprintln!("got ip header:\n{:02x?}", iph);
        // eprintln!("got tcp header:\n{:02x?}", tcph);
        // eprintln!("responding with {:02x?}", &buf[..buf.len() - unwritten]);

        nic.send(&buf[..unwritten])?;
        Ok(Some(c))
    }

    pub fn on_packet<'a>(
        &mut self,
        nic: &mut tun_tap::Iface,
        iph: etherparse::Ipv4HeaderSlice<'a>,
        tcph: etherparse::TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> io::Result<()> {
        // --- Validate Sequence Numbers (RFC 793 S3.3)

        // --- Acceptable ACK Check
        // SND.UNA < SEG.ACK =< SND.NXT (This can wrap)
        let ackn = tcph.acknowledgment_number();

        if !is_between_wrapped(self.send.una, ackn, self.send.nxt.wrapping_add(1)) {
            return Ok(());
        }

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

        if slen == 0 {
            // zero length segment has seperate rules for acceptance
            if self.recv.wnd == 0 {
                if seqn != self.recv.nxt {
                    return Ok(());
                }
            } else if !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn, wend) {
                return Ok(());
            }
        } else {
            if self.recv.wnd == 0 {
                return Ok(());
            } else if !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn, wend)
                && !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn + slen - 1, wend)
            {
                return Ok(());
            }
        }

        match self.state {
            State::SynRecvd => {
                // expect to get an ACK for out SYN
                if !tcph.ack() {
                    return Ok(());
                }
            }

            State::Estab => {
                todo!()
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
