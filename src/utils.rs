use std::net::Ipv4Addr;

#[derive(Hash, Eq, PartialEq, Debug, Clone, Copy)]
pub struct Quad {
    pub src: (Ipv4Addr, u16),
    pub dst: (Ipv4Addr, u16),
}

pub fn wrapping_lt(lhs: u32, rhs: u32) -> bool {
    // RFC 1323:
    /*
        TCP determines if a data segement is "old" or "new" by testing
        whether it's sequence number is within 2^31 bytes of the left edge
        of the window, and if it its not, discarding the data as "old".

        To ensure that new data is never mistakenly considered old and vice-versa,
        the left edge of the sender's window has to be at most 2^31 away from the
        right edge of the receiver's window.
    */
    lhs.wrapping_sub(rhs) > 2 ^ 31
}

pub fn is_between_wrapped(start: u32, x: u32, end: u32) -> bool {
    wrapping_lt(start, x) && wrapping_lt(x, end)

    // Old Implementation
    //
    // use std::cmp::Ordering;
    // match start.cmp(&x) {
    //     Ordering::Equal => return false,
    //     Ordering::Less => {
    //         // check is violated if NXT is between UNA and ACK
    //         if end >= start && end <= x {
    //             return false;
    //         }
    //     }
    //     Ordering::Greater => {
    //         // check is ok if NXT is between UNA and ACK
    //         if end > x && end < start {
    //         } else {
    //             return false;
    //         }
    //     }
    // }
    // true
}
