//! Synchronous rtnetlink: `ip link set up`, `ip addr add`, `ip route add default`.
//! The socket acts on the network namespace it was *created* in.
use std::io;
use std::net::{IpAddr, Ipv4Addr};

use netlink_packet_core::{
    NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REQUEST, NetlinkHeader, NetlinkMessage,
    NetlinkPayload,
};
use netlink_packet_route::{
    AddressFamily, RouteNetlinkMessage,
    address::{AddressAttribute, AddressMessage},
    link::{LinkFlags, LinkMessage},
    route::{RouteAddress, RouteAttribute, RouteHeader, RouteMessage, RouteProtocol, RouteScope, RouteType},
};
use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_ROUTE};

pub struct NetCfg {
    sock: Socket,
    seq: u32,
}

impl NetCfg {
    pub fn new() -> io::Result<Self> {
        let mut sock = Socket::new(NETLINK_ROUTE)?;
        sock.bind_auto()?;
        sock.connect(&SocketAddr::new(0, 0))?; // kernel
        Ok(Self { sock, seq: 0 })
    }

    /// Send one request with NLM_F_ACK and wait for the kernel's ACK/NACK.
    fn request(&mut self, msg: RouteNetlinkMessage, flags: u16) -> io::Result<()> {
        self.seq += 1;
        let mut hdr = NetlinkHeader::default();
        hdr.flags = NLM_F_REQUEST | NLM_F_ACK | flags;
        hdr.sequence_number = self.seq;
        let mut nl = NetlinkMessage::new(hdr, NetlinkPayload::from(msg));
        nl.finalize();
        let mut buf = vec![0; nl.buffer_len()];
        nl.serialize(&mut buf);
        self.sock.send(&buf, 0)?;

        let mut rx = vec![0u8; 8192];
        loop {
            let n = self.sock.recv(&mut &mut rx[..], 0)?;
            let reply = NetlinkMessage::<RouteNetlinkMessage>::deserialize(&rx[..n])
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            if reply.header.sequence_number != self.seq {
                continue;
            }
            return match reply.payload {
                // An "error" with code None is the ACK.
                NetlinkPayload::Error(e) if e.code.is_some() => Err(e.to_io()),
                NetlinkPayload::Error(_) => Ok(()),
                other => Err(io::Error::other(format!("unexpected reply: {other:?}"))),
            };
        }
    }

    /// ip link set <index> up
    pub fn link_up(&mut self, index: u32) -> io::Result<()> {
        let mut msg = LinkMessage::default();
        msg.header.index = index;
        msg.header.flags = LinkFlags::Up;
        msg.header.change_mask = LinkFlags::Up; // only touch IFF_UP
        self.request(RouteNetlinkMessage::SetLink(msg), 0)
    }

    /// ip addr add <addr>/<prefix> dev <index>
    pub fn add_address(&mut self, index: u32, addr: IpAddr, prefix: u8) -> io::Result<()> {
        let mut msg = AddressMessage::default();
        msg.header.family = match addr {
            IpAddr::V4(_) => AddressFamily::Inet,
            IpAddr::V6(_) => AddressFamily::Inet6,
        };
        msg.header.prefix_len = prefix;
        msg.header.index = index;
        // For IPv4 the kernel wants both IFA_LOCAL and IFA_ADDRESS (they differ only on p2p links).
        msg.attributes.push(AddressAttribute::Local(addr));
        msg.attributes.push(AddressAttribute::Address(addr));
        self.request(RouteNetlinkMessage::NewAddress(msg), NLM_F_CREATE | NLM_F_EXCL)
    }

    /// ip route add default via <gw> dev <index>
    pub fn add_default_route_v4(&mut self, index: u32, gw: Ipv4Addr) -> io::Result<()> {
        let mut msg = RouteMessage::default();
        msg.header.address_family = AddressFamily::Inet;
        msg.header.destination_prefix_length = 0; // 0.0.0.0/0 = default; no RTA_DST needed
        msg.header.table = RouteHeader::RT_TABLE_MAIN;
        msg.header.protocol = RouteProtocol::Static;
        msg.header.scope = RouteScope::Universe;
        msg.header.kind = RouteType::Unicast;
        msg.attributes.push(RouteAttribute::Gateway(RouteAddress::Inet(gw)));
        msg.attributes.push(RouteAttribute::Oif(index));
        self.request(RouteNetlinkMessage::NewRoute(msg), NLM_F_CREATE | NLM_F_EXCL)
    }
}

pub fn if_index(name: &str) -> io::Result<u32> {
    let c = std::ffi::CString::new(name).unwrap();
    match unsafe { libc::if_nametoindex(c.as_ptr()) } {
        0 => Err(io::Error::last_os_error()),
        i => Ok(i),
    }
}
