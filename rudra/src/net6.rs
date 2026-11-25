//! IPv6 только на петле `::1`. UDP и TCP копируют байты в памяти, как петля IPv4.
//! Другой адрес назначения — `ENETUNREACH`. Свой адрес, кроме `::` и `::1`, —
//! `EADDRNOTAVAIL`. IPv4-mapped (`::ffff:0:0/96`) — `EAFNOSUPPORT`: двойного
//! стека нет. Провода, NDP и netlink нет.
//!
//! Сумма верхнего уровня считается по RFC 8200 (псевдозаголовок IPv6). На петле
//! она не вкладывается в кадр. Ноль у UDP — не «суммы нет», в отличие от IPv4.

use alloc::vec::Vec;
use spin::Mutex;

const SOCKS: usize = 16;
const QLEN: usize = 4;
const DGRAM_MAX: usize = 4096;
const TCP_N: usize = 16;
const TCP_RX: usize = 8192;

pub const EAGAIN: i32 = 11;
pub const EFAULT: i32 = 14;
pub const EINVAL: i32 = 22;
pub const EPIPE: i32 = 32;
pub const ENFILE: i32 = 23;
pub const EAFNOSUPPORT: i32 = 97;
pub const EADDRINUSE: i32 = 98;
pub const EADDRNOTAVAIL: i32 = 99;
pub const ENETUNREACH: i32 = 101;
pub const EISCONN: i32 = 106;
pub const ENOTCONN: i32 = 107;
pub const ECONNREFUSED: i32 = 111;
pub const EDESTADDRREQ: i32 = 89;
pub const EMSGSIZE: i32 = 90;

pub const UNSPEC: [u8; 16] = [0; 16];
pub const LOOPBACK: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

pub fn is_unspec(addr: &[u8; 16]) -> bool {
    *addr == UNSPEC
}

pub fn is_loopback(addr: &[u8; 16]) -> bool {
    *addr == LOOPBACK
}

/// `::ffff:0:0/96`. Не петля и не «любой»: такой адрес не принимается.
pub fn is_v4mapped(addr: &[u8; 16]) -> bool {
    addr[..10].iter().all(|b| *b == 0) && addr[10] == 0xff && addr[11] == 0xff
}

fn check_local(addr: &[u8; 16]) -> Result<(), i32> {
    if is_v4mapped(addr) {
        return Err(EAFNOSUPPORT);
    }
    if is_unspec(addr) || is_loopback(addr) {
        Ok(())
    } else {
        Err(EADDRNOTAVAIL)
    }
}

fn check_dest(addr: &[u8; 16], port: u16) -> Result<(), i32> {
    if port == 0 || is_unspec(addr) {
        return Err(EINVAL);
    }
    if is_v4mapped(addr) {
        return Err(EAFNOSUPPORT);
    }
    if !is_loopback(addr) {
        return Err(ENETUNREACH);
    }
    Ok(())
}

/// Сумма UDP/TCP с псевдозаголовком IPv6. Поле суммы в `segment` — нули.
/// У UDP результат 0 заменяется на `0xFFFF`: ноль в кадре значит «суммы нет».
pub fn upper_checksum(src: &[u8; 16], dst: &[u8; 16], proto: u8, segment: &[u8]) -> u16 {
    let sum = finish_sum(pseudo_sum(src, dst, proto, segment.len()) + csum_add(0, segment));
    if proto == 17 && sum == 0 {
        0xffff
    } else {
        sum
    }
}

/// `true`, если сумма сошлась. Нулевое поле UDP на IPv6 — ошибка, не «не считали».
pub fn upper_sum_ok(src: &[u8; 16], dst: &[u8; 16], proto: u8, segment: &[u8]) -> bool {
    if proto == 17 {
        if segment.len() < 8 {
            return false;
        }
        let field = u16::from_be_bytes([segment[6], segment[7]]);
        if field == 0 {
            return false;
        }
    }
    finish_sum(pseudo_sum(src, dst, proto, segment.len()) + csum_add(0, segment)) == 0
}

fn pseudo_sum(src: &[u8; 16], dst: &[u8; 16], proto: u8, len: usize) -> u32 {
    let mut sum = csum_add(0, src);
    sum = csum_add(sum, dst);
    sum += (len as u32) >> 16;
    sum += (len as u32) & 0xffff;
    sum += u32::from(proto);
    sum
}

fn csum_add(mut sum: u32, data: &[u8]) -> u32 {
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    sum
}

fn finish_sum(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

struct Dgram {
    src: [u8; 16],
    src_port: u16,
    data: Vec<u8>,
}

struct UdpSock {
    refs: u8,
    addr: [u8; 16],
    port: u16,
    bound: bool,
    peer: Option<([u8; 16], u16)>,
    nonblock: bool,
    reuse: bool,
    broadcast: bool,
    q: Vec<Dgram>,
}

static UDP_TAB: Mutex<[Option<UdpSock>; SOCKS]> = Mutex::new([
    None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
]);
static NEXT_PORT: Mutex<u16> = Mutex::new(49152);

fn with_udp<R>(f: impl FnOnce(&mut [Option<UdpSock>; SOCKS]) -> R) -> R {
    x86_64::instructions::interrupts::without_interrupts(|| f(&mut UDP_TAB.lock()))
}

fn alloc_port(tab: &[Option<UdpSock>; SOCKS]) -> u16 {
    let mut next = NEXT_PORT.lock();
    for _ in 0..1000 {
        let port = *next;
        *next = if port >= 65000 { 49152 } else { port + 1 };
        if !udp_taken(tab, SOCKS, port) {
            return port;
        }
    }
    0
}

fn udp_taken(tab: &[Option<UdpSock>; SOCKS], except: usize, port: u16) -> bool {
    let reuse = tab
        .get(except)
        .and_then(|s| s.as_ref())
        .map(|s| s.reuse)
        .unwrap_or(false);
    tab.iter().enumerate().any(|(i, s)| {
        i != except
            && s.as_ref()
                .map(|s| s.bound && s.port == port && !(reuse && s.reuse))
                .unwrap_or(false)
    })
}

pub fn udp_open(nonblock: bool) -> Result<usize, i32> {
    with_udp(|tab| {
        for (i, slot) in tab.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(UdpSock {
                    refs: 1,
                    addr: UNSPEC,
                    port: 0,
                    bound: false,
                    peer: None,
                    nonblock,
                    reuse: false,
                    broadcast: false,
                    q: Vec::new(),
                });
                return Ok(i);
            }
        }
        Err(ENFILE)
    })
}

pub fn udp_addref(id: usize) {
    with_udp(|tab| {
        if let Some(Some(s)) = tab.get_mut(id) {
            s.refs = s.refs.saturating_add(1);
        }
    });
}

pub fn udp_close(id: usize) {
    with_udp(|tab| {
        let free = match tab.get_mut(id) {
            Some(Some(s)) => {
                s.refs = s.refs.saturating_sub(1);
                s.refs == 0
            }
            _ => false,
        };
        if free {
            tab[id] = None;
        }
    });
}

pub fn udp_nonblock(id: usize) -> bool {
    with_udp(|tab| {
        tab.get(id)
            .and_then(|s| s.as_ref())
            .map(|s| s.nonblock)
            .unwrap_or(false)
    })
}

pub fn udp_pending(id: usize) -> bool {
    with_udp(|tab| {
        tab.get(id)
            .and_then(|s| s.as_ref())
            .map(|s| !s.q.is_empty())
            .unwrap_or(false)
    })
}

pub fn udp_name(id: usize) -> Option<([u8; 16], u16)> {
    with_udp(|tab| {
        tab.get(id)
            .and_then(|s| s.as_ref())
            .filter(|s| s.bound)
            .map(|s| (s.addr, s.port))
    })
}

pub fn udp_peer(id: usize) -> Option<([u8; 16], u16)> {
    with_udp(|tab| tab.get(id).and_then(|s| s.as_ref()).and_then(|s| s.peer))
}

pub fn udp_bind(id: usize, addr: [u8; 16], port: u16) -> Result<(), i32> {
    check_local(&addr)?;
    with_udp(|tab| {
        if tab.get(id).and_then(|s| s.as_ref()).is_none() {
            return Err(EFAULT);
        }
        let port = if port == 0 { alloc_port(tab) } else { port };
        if port == 0 || udp_taken(tab, id, port) {
            return Err(EADDRINUSE);
        }
        let s = tab[id].as_mut().unwrap();
        s.addr = addr;
        s.port = port;
        s.bound = true;
        Ok(())
    })
}

pub fn udp_connect(id: usize, addr: [u8; 16], port: u16) -> Result<(), i32> {
    check_dest(&addr, port)?;
    with_udp(|tab| {
        if tab.get(id).and_then(|s| s.as_ref()).is_none() {
            return Err(EFAULT);
        }
        if !tab[id].as_ref().unwrap().bound {
            let port = alloc_port(tab);
            if port == 0 {
                return Err(EADDRINUSE);
            }
            let s = tab[id].as_mut().unwrap();
            s.port = port;
            s.addr = LOOPBACK;
            s.bound = true;
        }
        tab[id].as_mut().unwrap().peer = Some((addr, port));
        Ok(())
    })
}

pub fn udp_send(id: usize, data: &[u8], dst: Option<([u8; 16], u16)>) -> Result<usize, i32> {
    if data.len() > DGRAM_MAX {
        return Err(EMSGSIZE);
    }
    let (src, sport, dest) = with_udp(|tab| -> Result<_, i32> {
        if tab.get(id).and_then(|s| s.as_ref()).is_none() {
            return Err(EFAULT);
        }
        let dest = dst.or_else(|| tab[id].as_ref().unwrap().peer).ok_or(EDESTADDRREQ)?;
        check_dest(&dest.0, dest.1)?;
        if !tab[id].as_ref().unwrap().bound {
            let port = alloc_port(tab);
            if port == 0 {
                return Err(EADDRINUSE);
            }
            let s = tab[id].as_mut().unwrap();
            s.port = port;
            s.addr = LOOPBACK;
            s.bound = true;
        }
        let s = tab[id].as_ref().unwrap();
        let src = if is_unspec(&s.addr) { LOOPBACK } else { s.addr };
        Ok((src, s.port, dest))
    })?;
    deliver(dest.0, dest.1, src, sport, data);
    Ok(data.len())
}

pub fn udp_recv(id: usize, buf: &mut [u8]) -> Result<(usize, [u8; 16], u16), i32> {
    with_udp(|tab| {
        let Some(s) = tab.get_mut(id).and_then(|s| s.as_mut()) else {
            return Err(EFAULT);
        };
        if s.q.is_empty() {
            return Err(EAGAIN);
        }
        let d = s.q.remove(0);
        let n = d.data.len().min(buf.len());
        buf[..n].copy_from_slice(&d.data[..n]);
        Ok((n, d.src, d.src_port))
    })
}

pub fn udp_set_opt(id: usize, opt: u32, on: bool) -> Result<(), i32> {
    with_udp(|tab| {
        let Some(s) = tab.get_mut(id).and_then(|s| s.as_mut()) else {
            return Err(EFAULT);
        };
        match opt {
            2 => s.reuse = on,
            6 => s.broadcast = on,
            _ => return Err(EINVAL),
        }
        Ok(())
    })
}

pub fn udp_get_opt(id: usize, opt: u32) -> Result<i32, i32> {
    with_udp(|tab| {
        let Some(s) = tab.get(id).and_then(|s| s.as_ref()) else {
            return Err(EFAULT);
        };
        let on = match opt {
            2 => s.reuse,
            6 => s.broadcast,
            _ => return Err(EINVAL),
        };
        Ok(if on { 1 } else { 0 })
    })
}

fn deliver(dst: [u8; 16], dport: u16, src: [u8; 16], sport: u16, data: &[u8]) {
    with_udp(|tab| {
        for slot in tab.iter_mut().flatten() {
            if !slot.bound || slot.port != dport {
                continue;
            }
            if !is_unspec(&slot.addr) && slot.addr != dst {
                continue;
            }
            if slot.q.len() >= QLEN {
                continue;
            }
            slot.q.push(Dgram {
                src,
                src_port: sport,
                data: data.to_vec(),
            });
        }
    });
}

struct TcpSock {
    refs: u8,
    listen: bool,
    bound: bool,
    nonblock: bool,
    addr: [u8; 16],
    port: u16,
    peer_addr: [u8; 16],
    peer_port: u16,
    peer: Option<usize>,
    parent: Option<usize>,
    backlog_max: usize,
    backlog: Vec<usize>,
    rx: Vec<u8>,
    eof: bool,
    reuse: bool,
    broadcast: bool,
}

static TCP_TAB: Mutex<[Option<TcpSock>; TCP_N]> = Mutex::new([
    None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
]);

fn with_tcp<R>(f: impl FnOnce(&mut [Option<TcpSock>; TCP_N]) -> R) -> R {
    x86_64::instructions::interrupts::without_interrupts(|| f(&mut TCP_TAB.lock()))
}

fn tcp_fresh(nonblock: bool) -> TcpSock {
    TcpSock {
        refs: 1,
        listen: false,
        bound: false,
        nonblock,
        addr: UNSPEC,
        port: 0,
        peer_addr: UNSPEC,
        peer_port: 0,
        peer: None,
        parent: None,
        backlog_max: 0,
        backlog: Vec::new(),
        rx: Vec::new(),
        eof: false,
        reuse: false,
        broadcast: false,
    }
}

fn tcp_port_taken(tab: &[Option<TcpSock>; TCP_N], except: usize, port: u16) -> bool {
    let reuse = tab
        .get(except)
        .and_then(|s| s.as_ref())
        .map(|s| s.reuse)
        .unwrap_or(false);
    tab.iter().enumerate().any(|(i, s)| {
        i != except
            && s.as_ref()
                .map(|s| s.bound && s.port == port && s.listen && !(reuse && s.reuse))
                .unwrap_or(false)
    })
}

fn tcp_alloc_port(tab: &[Option<TcpSock>; TCP_N]) -> u16 {
    let mut next = NEXT_PORT.lock();
    for _ in 0..1000 {
        let port = *next;
        *next = if port >= 65000 { 49152 } else { port + 1 };
        if !tcp_port_taken(tab, TCP_N, port) {
            return port;
        }
    }
    0
}

pub fn tcp_open(nonblock: bool) -> Result<usize, i32> {
    with_tcp(|tab| {
        for (i, slot) in tab.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(tcp_fresh(nonblock));
                return Ok(i);
            }
        }
        Err(ENFILE)
    })
}

pub fn tcp_addref(id: usize) {
    with_tcp(|tab| {
        if let Some(Some(s)) = tab.get_mut(id) {
            s.refs = s.refs.saturating_add(1);
        }
    });
}

pub fn tcp_close(id: usize) {
    with_tcp(|tab| tcp_drop(tab, id));
}

fn tcp_drop(tab: &mut [Option<TcpSock>; TCP_N], id: usize) {
    let Some(Some(s)) = tab.get_mut(id) else {
        return;
    };
    s.refs = s.refs.saturating_sub(1);
    if s.refs > 0 {
        return;
    }
    let sock = tab[id].take().unwrap();
    if let Some(p) = sock.peer {
        if let Some(Some(ps)) = tab.get_mut(p) {
            if ps.peer == Some(id) {
                ps.peer = None;
            }
            ps.eof = true;
        }
    }
    if let Some(parent) = sock.parent {
        if let Some(Some(ls)) = tab.get_mut(parent) {
            ls.backlog.retain(|c| *c != id);
        }
    }
    for child in sock.backlog {
        if let Some(Some(c)) = tab.get_mut(child) {
            c.refs = 1;
            c.parent = None;
        }
        tcp_drop(tab, child);
    }
}

pub fn tcp_nonblock(id: usize) -> bool {
    with_tcp(|tab| {
        tab.get(id)
            .and_then(|s| s.as_ref())
            .map(|s| s.nonblock)
            .unwrap_or(false)
    })
}

pub fn tcp_set_nonblock(id: usize, on: bool) -> Result<(), i32> {
    with_tcp(|tab| {
        let Some(s) = tab.get_mut(id).and_then(|s| s.as_mut()) else {
            return Err(EFAULT);
        };
        s.nonblock = on;
        Ok(())
    })
}

pub fn tcp_pending(id: usize) -> bool {
    with_tcp(|tab| {
        tab.get(id)
            .and_then(|s| s.as_ref())
            .map(|s| !s.rx.is_empty() || s.eof || (s.listen && !s.backlog.is_empty()))
            .unwrap_or(false)
    })
}

pub fn tcp_name(id: usize) -> Option<([u8; 16], u16)> {
    with_tcp(|tab| {
        tab.get(id)
            .and_then(|s| s.as_ref())
            .filter(|s| s.bound)
            .map(|s| (s.addr, s.port))
    })
}

pub fn tcp_peer(id: usize) -> Option<([u8; 16], u16)> {
    with_tcp(|tab| {
        tab.get(id).and_then(|s| s.as_ref()).and_then(|s| {
            if s.peer.is_some() || s.eof {
                Some((s.peer_addr, s.peer_port))
            } else {
                None
            }
        })
    })
}

pub fn tcp_set_opt(id: usize, opt: u32, on: bool) -> Result<(), i32> {
    with_tcp(|tab| {
        let Some(s) = tab.get_mut(id).and_then(|s| s.as_mut()) else {
            return Err(EFAULT);
        };
        match opt {
            2 => s.reuse = on,
            6 => s.broadcast = on,
            _ => return Err(EINVAL),
        }
        Ok(())
    })
}

pub fn tcp_get_opt(id: usize, opt: u32) -> Result<i32, i32> {
    with_tcp(|tab| {
        let Some(s) = tab.get(id).and_then(|s| s.as_ref()) else {
            return Err(EFAULT);
        };
        match opt {
            2 => Ok(if s.reuse { 1 } else { 0 }),
            6 => Ok(if s.broadcast { 1 } else { 0 }),
            _ => Err(EINVAL),
        }
    })
}

pub fn tcp_bind(id: usize, addr: [u8; 16], port: u16) -> Result<(), i32> {
    check_local(&addr)?;
    with_tcp(|tab| {
        if tab.get(id).and_then(|s| s.as_ref()).is_none() {
            return Err(EFAULT);
        }
        if tab[id].as_ref().unwrap().listen || tab[id].as_ref().unwrap().peer.is_some() {
            return Err(EINVAL);
        }
        let port = if port == 0 { tcp_alloc_port(tab) } else { port };
        if port == 0 || tcp_port_taken(tab, id, port) {
            return Err(EADDRINUSE);
        }
        let s = tab[id].as_mut().unwrap();
        s.addr = addr;
        s.port = port;
        s.bound = true;
        Ok(())
    })
}

pub fn tcp_listen(id: usize, backlog: u64) -> Result<(), i32> {
    with_tcp(|tab| {
        let (bound, port, connected) = {
            let Some(cur) = tab.get(id).and_then(|s| s.as_ref()) else {
                return Err(EFAULT);
            };
            (cur.bound, cur.port, cur.peer.is_some())
        };
        if !bound || port == 0 {
            return Err(EINVAL);
        }
        if connected {
            return Err(EISCONN);
        }
        if tcp_port_taken(tab, id, port) {
            return Err(EADDRINUSE);
        }
        let s = tab[id].as_mut().unwrap();
        s.listen = true;
        let n = if backlog == 0 { 1 } else { backlog as usize };
        s.backlog_max = n.min(8);
        Ok(())
    })
}

pub fn tcp_accept(id: usize) -> Result<(usize, [u8; 16], u16), i32> {
    with_tcp(|tab| {
        let Some(s) = tab.get_mut(id).and_then(|s| s.as_mut()) else {
            return Err(EFAULT);
        };
        if !s.listen {
            return Err(EINVAL);
        }
        if s.backlog.is_empty() {
            return Err(EAGAIN);
        }
        let child = s.backlog.remove(0);
        let (addr, port) = match tab.get(child).and_then(|s| s.as_ref()) {
            Some(c) => (c.peer_addr, c.peer_port),
            None => return Err(EFAULT),
        };
        if let Some(c) = tab[child].as_mut() {
            c.parent = None;
        }
        Ok((child, addr, port))
    })
}

pub fn tcp_connect(id: usize, dst: [u8; 16], dst_port: u16) -> Result<(), i32> {
    check_dest(&dst, dst_port)?;
    with_tcp(|tab| {
        let (listening, connected) = {
            let Some(client) = tab.get(id).and_then(|s| s.as_ref()) else {
                return Err(EFAULT);
            };
            (client.listen, client.peer.is_some())
        };
        if listening {
            return Err(EINVAL);
        }
        if connected {
            return Err(EISCONN);
        }
        let listener = tab.iter().position(|s| {
            s.as_ref()
                .map(|s| s.listen && s.port == dst_port && (is_unspec(&s.addr) || s.addr == dst))
                .unwrap_or(false)
        });
        let Some(lid) = listener else {
            return Err(ECONNREFUSED);
        };
        if lid == id {
            return Err(EINVAL);
        }
        let (queued, limit, local) = {
            let ls = tab[lid].as_ref().unwrap();
            let local = if is_unspec(&ls.addr) { dst } else { ls.addr };
            (ls.backlog.len(), ls.backlog_max, local)
        };
        if queued >= limit {
            return Err(ECONNREFUSED);
        }
        let (already, existing) = {
            let s = tab[id].as_ref().unwrap();
            (s.bound, s.port)
        };
        let cport = if already {
            existing
        } else {
            let port = tcp_alloc_port(tab);
            if port == 0 {
                return Err(EADDRINUSE);
            }
            port
        };
        let child = tab.iter().position(|s| s.is_none());
        let Some(child) = child else {
            return Err(ENFILE);
        };
        tab[child] = Some(TcpSock {
            refs: 1,
            listen: false,
            bound: true,
            nonblock: false,
            addr: local,
            port: dst_port,
            peer_addr: LOOPBACK,
            peer_port: cport,
            peer: Some(id),
            parent: Some(lid),
            backlog_max: 0,
            backlog: Vec::new(),
            rx: Vec::new(),
            eof: false,
            reuse: false,
            broadcast: false,
        });
        {
            let s = tab[id].as_mut().unwrap();
            s.bound = true;
            s.addr = LOOPBACK;
            s.port = cport;
            s.peer_addr = dst;
            s.peer_port = dst_port;
            s.peer = Some(child);
            s.eof = false;
        }
        tab[lid].as_mut().unwrap().backlog.push(child);
        Ok(())
    })
}

pub fn tcp_send(id: usize, data: &[u8]) -> Result<usize, i32> {
    if data.is_empty() {
        return Ok(0);
    }
    with_tcp(|tab| {
        let (eof, peer) = {
            let Some(s) = tab.get(id).and_then(|s| s.as_ref()) else {
                return Err(EFAULT);
            };
            if s.listen {
                return Err(ENOTCONN);
            }
            (s.eof, s.peer)
        };
        let Some(p) = peer else {
            return Err(if eof { EPIPE } else { ENOTCONN });
        };
        if eof {
            return Err(EPIPE);
        }
        let Some(dest) = tab.get_mut(p).and_then(|s| s.as_mut()) else {
            return Err(EPIPE);
        };
        let space = TCP_RX.saturating_sub(dest.rx.len());
        if space == 0 {
            return Err(EAGAIN);
        }
        let n = space.min(data.len());
        dest.rx.extend_from_slice(&data[..n]);
        Ok(n)
    })
}

pub fn tcp_recv(id: usize, buf: &mut [u8]) -> Result<(usize, [u8; 16], u16), i32> {
    with_tcp(|tab| {
        let Some(s) = tab.get_mut(id).and_then(|s| s.as_mut()) else {
            return Err(EFAULT);
        };
        if s.listen {
            return Err(ENOTCONN);
        }
        if s.rx.is_empty() {
            if s.eof {
                return Ok((0, s.peer_addr, s.peer_port));
            }
            return Err(if s.peer.is_some() { EAGAIN } else { ENOTCONN });
        }
        let n = s.rx.len().min(buf.len());
        buf[..n].copy_from_slice(&s.rx[..n]);
        s.rx.drain(..n);
        Ok((n, s.peer_addr, s.peer_port))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{serial_print, serial_println};

    #[test_case]
    fn ipv6_loopback_udp_and_tcp() {
        serial_print!("test ipv6_loopback_udp_and_tcp... ");
        let mut seg = [0u8, 1, 0, 2, 0, 8, 0, 0];
        let sum = upper_checksum(&LOOPBACK, &LOOPBACK, 17, &seg);
        assert_eq!(sum, 0xFFD9, "udp checksum {:#x}", sum);
        seg[6..8].copy_from_slice(&sum.to_be_bytes());
        assert!(upper_sum_ok(&LOOPBACK, &LOOPBACK, 17, &seg));
        seg[6] = 0;
        seg[7] = 0;
        assert!(!upper_sum_ok(&LOOPBACK, &LOOPBACK, 17, &seg), "zero udp sum");

        let srv = udp_open(false).expect("udp");
        udp_bind(srv, UNSPEC, 19070).expect("bind");
        let cli = udp_open(false).expect("udp cli");
        let n = udp_send(cli, b"v6-loop", Some((LOOPBACK, 19070))).expect("send");
        assert_eq!(n, 7);
        let mut buf = [0u8; 16];
        let (n, src, sport) = udp_recv(srv, &mut buf).expect("recv");
        assert_eq!(&buf[..n], b"v6-loop");
        assert_eq!(src, LOOPBACK);
        assert_ne!(sport, 0);
        let mut far = [0u8; 16];
        far[0] = 0x20;
        far[1] = 0x01;
        far[15] = 1;
        assert_eq!(
            udp_send(cli, b"x", Some((far, 9))).expect_err("wire"),
            ENETUNREACH
        );
        let mut mapped = [0u8; 16];
        mapped[10] = 0xff;
        mapped[11] = 0xff;
        mapped[12] = 127;
        mapped[15] = 1;
        assert_eq!(
            udp_bind(cli, mapped, 19071).expect_err("mapped"),
            EAFNOSUPPORT
        );
        assert_eq!(
            udp_send(cli, b"x", Some((mapped, 9))).expect_err("mapped dest"),
            EAFNOSUPPORT
        );
        assert_eq!(
            udp_bind(cli, far, 19071).expect_err("not local"),
            EADDRNOTAVAIL
        );
        udp_close(cli);
        udp_close(srv);

        let lst = tcp_open(false).expect("tcp");
        tcp_bind(lst, UNSPEC, 19072).expect("tbind");
        tcp_listen(lst, 1).expect("listen");
        let client = tcp_open(false).expect("tcli");
        assert_eq!(
            tcp_connect(client, far, 80).expect_err("tcp wire"),
            ENETUNREACH
        );
        tcp_connect(client, LOOPBACK, 19072).expect("connect");
        let (acc, peer, pport) = tcp_accept(lst).expect("accept");
        assert_eq!(peer, LOOPBACK);
        assert_ne!(pport, 0);
        assert_eq!(tcp_send(client, b"ping").expect("tsend"), 4);
        let mut tbuf = [0u8; 8];
        let (n, _, _) = tcp_recv(acc, &mut tbuf).expect("trecv");
        assert_eq!(&tbuf[..n], b"ping");
        tcp_close(client);
        let (n, _, _) = tcp_recv(acc, &mut tbuf).expect("eof");
        assert_eq!(n, 0, "peer close is eof");
        tcp_close(acc);
        tcp_close(lst);
        let refused = tcp_open(false).expect("refused");
        assert_eq!(
            tcp_connect(refused, LOOPBACK, 19073).expect_err("closed"),
            ECONNREFUSED
        );
        tcp_close(refused);
        serial_println!("[ok]");
    }
}
