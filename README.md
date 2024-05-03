# TCP Implementation in Rust

## 1. Core Functionality

### RFC 793: "Transmission Control Protocol"

> Usually, the user space sends network requests to the Kernel using sockets and has a pointer to the kernel memory (that represents the TCP connection) inside the Kernel. Then, the Kernel already knows how to deliver packets to the internet.

> However, using Sockets for implementing our own TCP might cause conflicts as Kernel already implements it's own TCP to talk to the internet.

#### 1. Emulate network inside the user's space using a TUN device

- Hence, using a Linux feature called TUN/TAP provides packet reception and transmission for user space program. Instead of receiving and writing packets from a physical media, it receives them from user space program and writes them to the user program respectively.
- In this, Kernel creates a virtual space for us. So, Kernel treats the TUN interface as it's own network interface. So, any send the Kernel does turns into a receive for the user program and any write by the user program goes through the TUN, and appear to the kernel as a network IP packet.
- TUN has it's own IP Protocol and network metadata.

#### 2. TCP Packet Frame Format

- Flags [2 bytes]
- Proto [2 bytes]

  > 0x086dd Ethernet Type for IPv6 <br/>
  > 0x0800 ICMP - Protocol 1 (Ping) <br/>
  > TCP - Protocol 6

- Raw Protocol(IP, IPv6, etc) frame

### RFC 1122: "Requirements for Hosts - Communication Layers"

-

### RFC 2873: "TCP Processing of the IPv4 Precedence Field"

-

### RFC 5681: "TCP Congestion Control"

-
