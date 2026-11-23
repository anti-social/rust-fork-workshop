//! Minimal user-space TCP proxy behind a TAP device (IPv4 only, no retransmission).
//! The container's TCP connections are terminated here and re-opened as host sockets.
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddrV4, TcpStream, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::{thread, time};

const MY_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 1]; // answers ARP for every IP
const MSS: usize = 1460;
/// DNS queries from the container (UDP to port 53, any IP) are sent here: the host's
/// systemd-resolved stub, which knows the host's real upstream and VPN DNS servers.
const HOST_DNS: &str = "127.0.0.53:53";
const FIN: u8 = 0x01;
const SYN: u8 = 0x02;
const RST: u8 = 0x04;
const PSH: u8 = 0x08;
const ACK: u8 = 0x10;

/// (container ip, container port, remote ip, remote port)
type Key = (Ipv4Addr, u16, Ipv4Addr, u16);

struct State {
    snd_nxt: u32, // next seq we send to the container
    snd_una: u32, // oldest seq the container hasn't ACKed
    wnd: u32,     // container's receive window
    rcv_nxt: u32, // next seq we expect from the container
    fin_rcvd: bool,
    fin_sent: bool,
}

struct Conn {
    stream: TcpStream,
    st: Arc<Mutex<State>>,
    isn: u32,
}

pub fn run(tap: File) -> std::io::Result<()> {
    let tap = Arc::new(tap);
    let mut conns: HashMap<Key, Conn> = HashMap::new();
    let mut buf = vec![0u8; 65536];
    loop {
        let n = (&*tap).read(&mut buf)?;
        let f = &buf[..n];
        match f.get(12..14) {
            Some([8, 6]) if n >= 42 => arp_reply(&tap, f),
            Some([8, 0]) if n >= 54 && f[23] == 6 => tcp_in(&tap, &mut conns, f),
            Some([8, 0]) if n >= 42 && f[23] == 17 => dns_in(&tap, f),
            _ => {} // IPv6, other UDP, ICMP, ... ignored
        }
    }
}

fn arp_reply(tap: &File, req: &[u8]) {
    let a = &req[14..42]; // htype ptype hlen plen op(6..8) sha(8..14) spa(14..18) tha tpa(24..28)
    if a[6..8] != [0, 1] || a[14..18] == a[24..28] {
        return; // not a request, or a gratuitous ARP for its own address
    }
    let mut f = Vec::with_capacity(42);
    f.extend_from_slice(&req[6..12]); // to the asker
    f.extend_from_slice(&MY_MAC);
    f.extend_from_slice(&[8, 6, 0, 1, 8, 0, 6, 4, 0, 2]); // ARP reply
    f.extend_from_slice(&MY_MAC);
    f.extend_from_slice(&a[24..28]); // "I am <the IP you asked for>"
    f.extend_from_slice(&a[8..18]);
    let _ = (&*tap).write(&f);
}

fn tcp_in(tap: &Arc<File>, conns: &mut HashMap<Key, Conn>, f: &[u8]) {
    let ip = &f[14..];
    let ihl = (ip[0] & 0x0f) as usize * 4;
    let total = (u16::from_be_bytes([ip[2], ip[3]]) as usize).min(ip.len());
    let tcp = &ip[ihl..total];
    let be16 = |b: &[u8]| u16::from_be_bytes([b[0], b[1]]);
    let be32 = |b: &[u8]| u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
    let k: Key = (
        Ipv4Addr::from(be32(&ip[12..])), be16(&tcp[0..]),
        Ipv4Addr::from(be32(&ip[16..])), be16(&tcp[2..]),
    );
    let (seq, ack, flags, wnd) = (be32(&tcp[4..]), be32(&tcp[8..]), tcp[13], be16(&tcp[14..]) as u32);
    let data = &tcp[(tcp[12] >> 4) as usize * 4..];
    let mac: [u8; 6] = f[6..12].try_into().unwrap();

    if flags & RST != 0 {
        conns.remove(&k);
        return;
    }
    if flags & SYN != 0 {
        let mss = [2, 4, (MSS >> 8) as u8, MSS as u8];
        if let Some(c) = conns.get(&k) {
            // SYN retransmitted: repeat our SYN-ACK
            send_tcp(tap, &k, mac, c.isn, seq.wrapping_add(1), SYN | ACK, &mss, &[]);
            return;
        }
        // Open the real connection from the host. (Blocking: stalls other flows meanwhile.)
        let dst = SocketAddrV4::new(k.2, k.3).into();
        let Ok(stream) = TcpStream::connect_timeout(&dst, Duration::from_secs(5)) else {
            send_tcp(tap, &k, mac, 0, seq.wrapping_add(1), RST | ACK, &[], &[]);
            return;
        };
        let isn = time::SystemTime::now().duration_since(time::UNIX_EPOCH).unwrap().subsec_nanos();
        let st = Arc::new(Mutex::new(State {
            snd_nxt: isn.wrapping_add(1),
            snd_una: isn.wrapping_add(1),
            wnd,
            rcv_nxt: seq.wrapping_add(1),
            fin_rcvd: false,
            fin_sent: false,
        }));
        // No window-scale option in our SYN-ACK => scaling is off in both directions.
        send_tcp(tap, &k, mac, isn, seq.wrapping_add(1), SYN | ACK, &mss, &[]);
        let (rd, tap2, st2) = (stream.try_clone().unwrap(), tap.clone(), st.clone());
        thread::spawn(move || remote_to_container(rd, tap2, k, mac, st2));
        conns.insert(k, Conn { stream, st, isn });
        return;
    }

    let Some(c) = conns.get_mut(&k) else { return };
    let st = c.st.clone();
    let (in_order, snd_nxt, rcv_nxt) = {
        let mut s = st.lock().unwrap();
        if flags & ACK != 0 && ack.wrapping_sub(s.snd_una) <= s.snd_nxt.wrapping_sub(s.snd_una) {
            s.snd_una = ack;
            s.wnd = wnd;
        }
        let in_order = seq == s.rcv_nxt;
        if in_order {
            s.rcv_nxt = s.rcv_nxt.wrapping_add(data.len() as u32);
            if flags & FIN != 0 {
                s.rcv_nxt = s.rcv_nxt.wrapping_add(1);
                s.fin_rcvd = true;
            }
        }
        (in_order, s.snd_nxt, s.rcv_nxt)
    };
    if !data.is_empty() || flags & FIN != 0 {
        if in_order {
            // Container -> remote. ACK only after the host kernel took the bytes.
            if c.stream.write_all(data).is_err() {
                send_tcp(tap, &k, mac, snd_nxt, rcv_nxt, RST | ACK, &[], &[]);
                conns.remove(&k);
                return;
            }
            if flags & FIN != 0 {
                let _ = c.stream.shutdown(Shutdown::Write);
            }
        }
        // in order: ACK the new data; otherwise re-ACK what we have and the container retransmits
        send_tcp(tap, &k, mac, snd_nxt, rcv_nxt, ACK, &[], &[]);
    }
    let s = st.lock().unwrap();
    if s.fin_rcvd && s.fin_sent && s.snd_una == s.snd_nxt {
        drop(s);
        conns.remove(&k); // both sides closed and our FIN was ACKed
    }
}

/// UDP to port 53 (whatever the destination IP) is answered by the host's resolver.
fn dns_in(tap: &Arc<File>, f: &[u8]) {
    let ip = &f[14..];
    let ihl = (ip[0] & 0x0f) as usize * 4;
    let total = (u16::from_be_bytes([ip[2], ip[3]]) as usize).min(ip.len());
    let udp = &ip[ihl..total];
    if udp.len() < 8 || u16::from_be_bytes([udp[2], udp[3]]) != 53 {
        return;
    }
    let k: Key = (
        Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]),
        u16::from_be_bytes([udp[0], udp[1]]),
        Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]),
        53,
    );
    let mac: [u8; 6] = f[6..12].try_into().unwrap();
    let query = udp[8..].to_vec();
    let tap = tap.clone();
    // One short-lived thread per query, so a slow lookup doesn't block the TAP loop.
    thread::spawn(move || {
        let ask = || -> std::io::Result<Vec<u8>> {
            let sock = UdpSocket::bind("0.0.0.0:0")?;
            sock.connect(HOST_DNS)?; // only accept replies from the resolver
            sock.set_read_timeout(Some(Duration::from_secs(5)))?;
            sock.send(&query)?;
            let mut buf = vec![0u8; 1472]; // max UDP payload in a 1500-byte frame
            let n = sock.recv(&mut buf)?;
            buf.truncate(n);
            Ok(buf)
        };
        if let Ok(answer) = ask() {
            send_udp(&tap, &k, mac, &answer);
        } // on error/timeout stay silent: the container's resolver retries
    });
}

/// Build Ethernet + IPv4 + UDP "from k.2:k.3" to the container.
/// UDP checksum 0 means "no checksum", which IPv4 allows.
fn send_udp(tap: &File, k: &Key, mac: [u8; 6], data: &[u8]) {
    let (cip, cport, rip, rport) = *k;
    let udp_len = 8 + data.len();
    let mut f = Vec::with_capacity(34 + udp_len);
    f.extend_from_slice(&mac);
    f.extend_from_slice(&MY_MAC);
    f.extend_from_slice(&[8, 0]);
    // IPv4: version/IHL, TOS, length, ID, DF, TTL 64, proto 17 (UDP), checksum, src, dst
    f.extend_from_slice(&[0x45, 0]);
    f.extend_from_slice(&((20 + udp_len) as u16).to_be_bytes());
    f.extend_from_slice(&[0, 0, 0x40, 0, 64, 17, 0, 0]);
    f.extend_from_slice(&rip.octets());
    f.extend_from_slice(&cip.octets());
    let c = checksum(sum(0, &f[14..34]));
    f[24..26].copy_from_slice(&c.to_be_bytes());
    // UDP: src port, dst port, length, checksum
    f.extend_from_slice(&rport.to_be_bytes());
    f.extend_from_slice(&cport.to_be_bytes());
    f.extend_from_slice(&(udp_len as u16).to_be_bytes());
    f.extend_from_slice(&[0, 0]);
    f.extend_from_slice(data);
    let _ = (&*tap).write(&f);
}

/// Remote -> container, respecting the container's receive window.
fn remote_to_container(mut rd: TcpStream, tap: Arc<File>, k: Key, mac: [u8; 6], st: Arc<Mutex<State>>) {
    let mut buf = [0u8; MSS];
    loop {
        let room = loop {
            let s = st.lock().unwrap();
            let in_flight = s.snd_nxt.wrapping_sub(s.snd_una);
            if in_flight < s.wnd {
                break (s.wnd - in_flight) as usize;
            }
            drop(s);
            thread::sleep(Duration::from_millis(1));
        };
        let n = rd.read(&mut buf[..room.min(MSS)]).unwrap_or(0);
        let mut s = st.lock().unwrap();
        if n == 0 {
            // remote closed (or error): send FIN
            send_tcp(&tap, &k, mac, s.snd_nxt, s.rcv_nxt, FIN | ACK, &[], &[]);
            s.snd_nxt = s.snd_nxt.wrapping_add(1);
            s.fin_sent = true;
            return;
        }
        send_tcp(&tap, &k, mac, s.snd_nxt, s.rcv_nxt, PSH | ACK, &[], &buf[..n]);
        s.snd_nxt = s.snd_nxt.wrapping_add(n as u32);
    }
}

/// Build Ethernet + IPv4 + TCP "from the remote host" and write it into the TAP.
fn send_tcp(tap: &File, k: &Key, mac: [u8; 6], seq: u32, ack: u32, flags: u8, opts: &[u8], data: &[u8]) {
    let (cip, cport, rip, rport) = *k;
    let tcp_len = 20 + opts.len() + data.len();
    let mut f = Vec::with_capacity(34 + tcp_len);
    f.extend_from_slice(&mac);
    f.extend_from_slice(&MY_MAC);
    f.extend_from_slice(&[8, 0]);
    // IPv4: version/IHL, TOS, length, ID, DF, TTL 64, proto 6, checksum, src, dst
    f.extend_from_slice(&[0x45, 0]);
    f.extend_from_slice(&((20 + tcp_len) as u16).to_be_bytes());
    f.extend_from_slice(&[0, 0, 0x40, 0, 64, 6, 0, 0]);
    f.extend_from_slice(&rip.octets());
    f.extend_from_slice(&cip.octets());
    let c = checksum(sum(0, &f[14..34]));
    f[24..26].copy_from_slice(&c.to_be_bytes());
    // TCP
    f.extend_from_slice(&rport.to_be_bytes());
    f.extend_from_slice(&cport.to_be_bytes());
    f.extend_from_slice(&seq.to_be_bytes());
    f.extend_from_slice(&ack.to_be_bytes());
    f.extend_from_slice(&[(((20 + opts.len()) / 4) as u8) << 4, flags, 0xff, 0xff, 0, 0, 0, 0]);
    f.extend_from_slice(opts);
    f.extend_from_slice(data);
    let pseudo = sum(sum(sum(6 + tcp_len as u32, &rip.octets()), &cip.octets()), &f[34..]);
    f[50..52].copy_from_slice(&checksum(pseudo).to_be_bytes());
    let _ = (&*tap).write(&f);
}

fn sum(mut acc: u32, data: &[u8]) -> u32 {
    for ch in data.chunks(2) {
        acc += u16::from_be_bytes([ch[0], *ch.get(1).unwrap_or(&0)]) as u32;
    }
    acc
}

fn checksum(mut acc: u32) -> u16 {
    while acc >> 16 != 0 {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    !(acc as u16)
}
