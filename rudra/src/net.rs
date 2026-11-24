//! IPv4, UDP и TCP. Петля `127.0.0.0/8` и провод через virtio-net:
//! ARP на восемь соседей, DHCP, скользящее окно и медленный старт.
//! Исходящий UDP считает сумму. Входящая сумма 0 на IPv4 значит «не считали»
//! и принимается: так QEMU отдаёт DHCP.
//! Датаграмма длиннее 4096 байт — `EMSGSIZE`. В провод уходит не больше
//! 1472. `SO_REUSEADDR` и `SO_BROADCAST` хранятся на сокете.
//! IPv6 и netlink нет.

use alloc::vec;
use alloc::vec::Vec;
use spin::Mutex;

const SOCKS: usize = 16;
const QLEN: usize = 4;
/// Потолок датаграммы в памяти сокета. В провод — отдельно, по Ethernet MTU.
pub const DGRAM_MAX: usize = 4096;
const WIRE_DGRAM_MAX: usize = 1472;

pub const EAGAIN: i32 = 11;
pub const EFAULT: i32 = 14;
pub const EINVAL: i32 = 22;
pub const ENFILE: i32 = 23;
pub const EDESTADDRREQ: i32 = 89;
pub const EMSGSIZE: i32 = 90;
pub const EPIPE: i32 = 32;
pub const EADDRINUSE: i32 = 98;
pub const EADDRNOTAVAIL: i32 = 99;
pub const ENETDOWN: i32 = 100;
pub const ENETUNREACH: i32 = 101;
pub const EISCONN: i32 = 106;
pub const ENOTCONN: i32 = 107;
pub const ECONNREFUSED: i32 = 111;
pub const ETIMEDOUT: i32 = 110;
pub const EINPROGRESS: i32 = 115;
pub const EINTR: i32 = 4;
pub const EACCES: i32 = 13;

struct Dgram {
    src: u32,
    src_port: u16,
    data: Vec<u8>,
}

struct Sock {
    refs: u8,
    addr: u32,
    port: u16,
    bound: bool,
    peer: Option<(u32, u16)>,
    nonblock: bool,
    reuse: bool,
    broadcast: bool,
    q: Vec<Dgram>,
}

const ARP_SLOTS: usize = 8;

#[derive(Clone, Copy)]
struct ArpSlot {
    ip: u32,
    mac: [u8; 6],
}

struct Iface {
    mac: [u8; 6],
    up: bool,
    ip: u32,
    mask: u32,
    gw: u32,
    arp: [ArpSlot; ARP_SLOTS],
    arp_hand: usize,
}

static SOCKS_TAB: Mutex<[Option<Sock>; SOCKS]> = Mutex::new([None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None]);
static IFACE: Mutex<Iface> = Mutex::new(Iface {
    mac: [0; 6],
    up: false,
    ip: 0,
    mask: 0,
    gw: 0,
    arp: [ArpSlot {
        ip: 0,
        mac: [0; 6],
    }; ARP_SLOTS],
    arp_hand: 0,
});
static NEXT_PORT: Mutex<u16> = Mutex::new(49152);

pub fn init() {
    match crate::virtio_net::init() {
        Ok(mac) => {
            let mut iface = IFACE.lock();
            iface.mac = mac;
            iface.up = true;
        }
        Err(e) => {
            crate::serial_println!("[virtio-net] no device ({})", e);
            return;
        }
    }
    // Адрес с карты появляется при загрузке, а не по первому запросу.
    // Без сети в QEMU (тестовые образы) просто отмечаем неудачу и живём дальше.
    if let Err(e) = dhcp() {
        crate::serial_println!("[net] dhcp on boot failed: {}", e);
    }
}

fn with_socks<R>(f: impl FnOnce(&mut [Option<Sock>; SOCKS]) -> R) -> R {
    x86_64::instructions::interrupts::without_interrupts(|| f(&mut SOCKS_TAB.lock()))
}

fn with_iface<R>(f: impl FnOnce(&mut Iface) -> R) -> R {
    x86_64::instructions::interrupts::without_interrupts(|| f(&mut IFACE.lock()))
}

pub fn udp_open(nonblock: bool) -> Result<usize, i32> {
    with_socks(|tab| {
        for (i, slot) in tab.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(Sock {
                    refs: 1,
                    addr: 0,
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
    with_socks(|tab| {
        if let Some(Some(s)) = tab.get_mut(id) {
            s.refs = s.refs.saturating_add(1);
        }
    });
}

pub fn udp_close(id: usize) {
    with_socks(|tab| {
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
    with_socks(|tab| tab.get(id).and_then(|s| s.as_ref()).map(|s| s.nonblock).unwrap_or(false))
}

pub fn udp_pending(id: usize) -> bool {
    pump();
    with_socks(|tab| {
        tab.get(id)
            .and_then(|s| s.as_ref())
            .map(|s| !s.q.is_empty())
            .unwrap_or(false)
    })
}

pub fn udp_name(id: usize) -> Option<(u32, u16)> {
    with_socks(|tab| {
        tab.get(id)
            .and_then(|s| s.as_ref())
            .filter(|s| s.bound)
            .map(|s| (s.addr, s.port))
    })
}

pub fn udp_peer(id: usize) -> Option<(u32, u16)> {
    with_socks(|tab| tab.get(id).and_then(|s| s.as_ref()).and_then(|s| s.peer))
}

pub fn udp_bind(id: usize, addr: u32, port: u16) -> Result<(), i32> {
    if !addr_ok(addr) {
        return Err(EADDRNOTAVAIL);
    }
    with_socks(|tab| {
        if tab.get(id).and_then(|s| s.as_ref()).is_none() {
            return Err(EFAULT);
        }
        let port = if port == 0 { alloc_port(tab) } else { port };
        if port == 0 || taken(tab, id, port) {
            return Err(EADDRINUSE);
        }
        let s = tab[id].as_mut().unwrap();
        s.addr = addr;
        s.port = port;
        s.bound = true;
        Ok(())
    })
}

pub fn udp_connect(id: usize, addr: u32, port: u16) -> Result<(), i32> {
    if port == 0 || addr == 0 {
        return Err(EINVAL);
    }
    with_socks(|tab| {
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
            s.bound = true;
        }
        tab[id].as_mut().unwrap().peer = Some((addr, port));
        Ok(())
    })
}

pub fn udp_send(id: usize, data: &[u8], dst: Option<(u32, u16)>) -> Result<usize, i32> {
    if data.len() > DGRAM_MAX {
        return Err(EMSGSIZE);
    }
    let (src, sport, dest, broadcast) = with_socks(|tab| -> Result<_, i32> {
        if tab.get(id).and_then(|s| s.as_ref()).is_none() {
            return Err(EFAULT);
        }
        let dest = dst
            .or_else(|| tab[id].as_ref().unwrap().peer)
            .ok_or(EDESTADDRREQ)?;
        if dest.1 == 0 || dest.0 == 0 {
            return Err(EINVAL);
        }
        if !tab[id].as_ref().unwrap().bound {
            let port = alloc_port(tab);
            if port == 0 {
                return Err(EADDRINUSE);
            }
            let s = tab[id].as_mut().unwrap();
            s.port = port;
            s.bound = true;
        }
        let s = tab[id].as_ref().unwrap();
        let src = if s.addr != 0 {
            s.addr
        } else if is_loopback(dest.0) {
            0x7f00_0001
        } else {
            0
        };
        Ok((src, s.port, dest, s.broadcast))
    })?;
    let src = if src != 0 { src } else { our_ip() };
    let bcast = dest.0 == 0xffff_ffff || directed_broadcast(dest.0);
    if bcast && !broadcast {
        return Err(EACCES);
    }
    if is_loopback(dest.0) || (src != 0 && dest.0 == src) {
        deliver(dest.0, dest.1, src, sport, data);
        return Ok(data.len());
    }
    if data.len() > WIRE_DGRAM_MAX {
        return Err(EMSGSIZE);
    }
    if !iface_up() || src == 0 {
        return Err(ENETDOWN);
    }
    send_udp(src, sport, dest.0, dest.1, data)?;
    if dest.0 == 0xffff_ffff {
        deliver(dest.0, dest.1, src, sport, data);
    }
    Ok(data.len())
}

pub fn udp_recv(id: usize, buf: &mut [u8]) -> Result<(usize, u32, u16), i32> {
    pump();
    with_socks(|tab| {
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

/// Забрать кадры с карты и разложить UDP по сокетам.
pub fn pump() {
    if !crate::virtio_net::present() {
        return;
    }
    let mut buf = [0u8; 1600];
    for _ in 0..16 {
        let Some(n) = crate::virtio_net::recv_frame(&mut buf) else {
            break;
        };
        handle_frame(&buf[..n]);
    }
    tcp_retransmit();
}

/// Повтор неподтверждённого: головной сегмент каждого сокета, у которого
/// RTO вышел. За RTO_TC попыток без ACK — разрыв (eof), как таймаут читателя.
const RTO_NS: u64 = 500_000_000;
const RTO_TC: u8 = 8;
/// Медленный старт: окно растёт на число подтверждённых байт, пока не
/// упрётся в `ssthresh`, дальше — на MSS²/cwnd за ACK. Потолок 64 КиБ.
const MSS: u32 = 1280;
const CWND_MAX: u32 = 64 * 1024;

fn tcp_retransmit() {
    let now = crate::time::monotonic_ns();
    let mut jobs: Vec<(u32, u16, u32, u16, u32, u32, Vec<u8>)> = Vec::new();
    with_tcp(|tab| {
        for s in tab.iter_mut().flatten() {
            if !s.wire || !s.estab || s.unacked.is_empty() {
                continue;
            }
            let inflight: u32 = s.unacked.iter().map(|(_, d, _)| d.len() as u32).sum();
            let due = s
                .unacked
                .iter()
                .position(|(_, _, last)| now.saturating_sub(*last) > RTO_NS);
            let Some(due) = due else { continue };
            s.unacked[due].2 = now;
            let seq = s.unacked[due].0;
            let data = s.unacked[due].1.clone();
            s.rtx = s.rtx.saturating_add(1);
            // Потеря: окно схлопывается до одного MSS, порог — половина полёта.
            s.ssthresh = (inflight / 2).max(MSS * 2);
            s.cwnd = MSS;
            if s.rtx >= RTO_TC {
                // Пир молчит слишком долго: закрываем передачу.
                s.eof = true;
                s.estab = false;
                s.unacked.clear();
                continue;
            }
            jobs.push((s.addr, s.port, s.peer_addr, s.peer_port, seq, s.rnext, data));
        }
    });
    for (a, p, pa, pp, seq, ack, data) in jobs {
        let _ = send_tcp(a, p, pa, pp, seq, ack, TH_ACK | TH_PSH, &data);
    }
}

pub fn our_ip() -> u32 {
    with_iface(|iface| iface.ip)
}

pub fn gateway() -> u32 {
    with_iface(|iface| iface.gw)
}

pub fn dhcp() -> Result<u32, &'static str> {
    if !crate::virtio_net::present() {
        return Err("no dev");
    }
    let mac = with_iface(|iface| iface.mac);
    let xid = (crate::time::monotonic_ns() as u32) | 1;
    let mut offer_ip = 0u32;
    let mut server = 0u32;
    for _ in 0..4 {
        let frame = build_dhcp(&mac, xid, 1, 0, 0);
        crate::virtio_net::send_frame(&frame).map_err(|_| "tx")?;
        if let Some(info) = wait_dhcp(xid, 2) {
            offer_ip = info.yiaddr;
            server = info.server;
            break;
        }
        crate::serial_println!("[net] dhcp discover retry");
    }
    if offer_ip == 0 {
        return Err("no offer");
    }
    crate::serial_println!(
        "[net] dhcp offer {}.{}.{}.{} server {}.{}.{}.{}",
        offer_ip >> 24,
        (offer_ip >> 16) & 255,
        (offer_ip >> 8) & 255,
        offer_ip & 255,
        server >> 24,
        (server >> 16) & 255,
        (server >> 8) & 255,
        server & 255
    );
    for _ in 0..4 {
        let frame = build_dhcp(&mac, xid, 3, offer_ip, server);
        crate::virtio_net::send_frame(&frame).map_err(|_| "tx")?;
        if let Some(info) = wait_dhcp(xid, 5) {
            let mask = if info.mask == 0 { 0xffff_ff00 } else { info.mask };
            // QEMU user-net шлюз — адрес сети + 2, если опция 3 не пришла.
            let gw = if info.gw == 0 {
                (info.yiaddr & mask) | 2
            } else {
                info.gw
            };
            with_iface(|iface| {
                iface.ip = info.yiaddr;
                iface.mask = mask;
                iface.gw = gw;
            });
            crate::serial_println!(
                "[net] dhcp ack {}.{}.{}.{}",
                info.yiaddr >> 24,
                (info.yiaddr >> 16) & 255,
                (info.yiaddr >> 8) & 255,
                info.yiaddr & 255
            );
            return Ok(info.yiaddr);
        }
    }
    Err("no ack")
}

pub fn arp_resolve(ip: u32) -> Result<[u8; 6], &'static str> {
    if let Some(mac) = arp_cached(ip) {
        return Ok(mac);
    }
    let (our_mac, our) = with_iface(|iface| (iface.mac, iface.ip));
    if our == 0 {
        return Err("no ip");
    }
    for _ in 0..3 {
        let frame = build_arp(&our_mac, our, ip, 1, &[0; 6]);
        crate::virtio_net::send_frame(&frame).map_err(|_| "tx")?;
        let deadline = crate::time::monotonic_ns().saturating_add(300_000_000);
        let mut buf = [0u8; 1600];
        while crate::time::monotonic_ns() < deadline {
            let Some(n) = crate::virtio_net::recv_frame(&mut buf) else {
                core::hint::spin_loop();
                continue;
            };
            handle_frame(&buf[..n]);
            if let Some(mac) = arp_cached(ip) {
                return Ok(mac);
            }
        }
    }
    Err("no arp")
}

fn arp_cached(ip: u32) -> Option<[u8; 6]> {
    with_iface(|iface| arp_find(iface, ip))
}

fn arp_find(iface: &Iface, ip: u32) -> Option<[u8; 6]> {
    iface.arp.iter().find(|s| s.ip == ip && s.mac != [0; 6]).map(|s| s.mac)
}

fn arp_learn(iface: &mut Iface, ip: u32, mac: [u8; 6]) {
    if ip == 0 || mac == [0; 6] {
        return;
    }
    if let Some(slot) = iface.arp.iter_mut().find(|s| s.ip == ip) {
        slot.mac = mac;
        return;
    }
    if let Some(slot) = iface.arp.iter_mut().find(|s| s.ip == 0) {
        *slot = ArpSlot { ip, mac };
        return;
    }
    let hand = iface.arp_hand % ARP_SLOTS;
    iface.arp[hand] = ArpSlot { ip, mac };
    iface.arp_hand = (hand + 1) % ARP_SLOTS;
}

fn iface_up() -> bool {
    with_iface(|iface| iface.up)
}

fn addr_ok(addr: u32) -> bool {
    addr == 0 || is_loopback(addr) || addr == our_ip()
}

fn is_loopback(addr: u32) -> bool {
    addr >> 24 == 127
}

fn alloc_port(tab: &[Option<Sock>; SOCKS]) -> u16 {
    let mut next = NEXT_PORT.lock();
    for _ in 0..1000 {
        let port = *next;
        *next = if port >= 65000 { 49152 } else { port + 1 };
        if !taken(tab, SOCKS, port) {
            return port;
        }
    }
    0
}

fn taken(tab: &[Option<Sock>; SOCKS], except: usize, port: u16) -> bool {
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

pub fn udp_set_opt(id: usize, opt: u32, on: bool) -> Result<(), i32> {
    with_socks(|tab| {
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
    with_socks(|tab| {
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

fn directed_broadcast(addr: u32) -> bool {
    let (ip, mask) = with_iface(|iface| (iface.ip, iface.mask));
    if ip == 0 || mask == 0 || mask == 0xffff_ffff {
        return false;
    }
    addr != ip && (addr & mask) == (ip & mask) && (addr & !mask) == !mask
}

fn deliver(dst: u32, dport: u16, src: u32, sport: u16, data: &[u8]) {
    with_socks(|tab| {
        for slot in tab.iter_mut().flatten() {
            if !slot.bound || slot.port != dport {
                continue;
            }
            if slot.addr != 0 && slot.addr != dst && dst != 0xffff_ffff {
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

fn send_udp(src: u32, sport: u16, dst: u32, dport: u16, payload: &[u8]) -> Result<(), i32> {
    let (mac, mask, gw) = with_iface(|iface| (iface.mac, iface.mask, iface.gw));
    let on_link = mask != 0 && (dst & mask) == (src & mask);
    let next = if dst == 0xffff_ffff {
        [0xff; 6]
    } else if on_link {
        arp_resolve(dst).map_err(|_| ENETDOWN)?
    } else if gw != 0 {
        arp_resolve(gw).map_err(|_| ENETDOWN)?
    } else {
        return Err(ENETDOWN);
    };
    let frame = build_udp_frame(&mac, &next, src, dst, sport, dport, payload);
    crate::virtio_net::send_frame(&frame).map_err(|_| EFAULT)?;
    Ok(())
}

struct DhcpInfo {
    yiaddr: u32,
    server: u32,
    mask: u32,
    gw: u32,
}

fn wait_dhcp(xid: u32, want: u8) -> Option<DhcpInfo> {
    let deadline = crate::time::monotonic_ns().saturating_add(400_000_000);
    let mut buf = [0u8; 1600];
    while crate::time::monotonic_ns() < deadline {
        let Some(n) = crate::virtio_net::recv_frame(&mut buf) else {
            core::hint::spin_loop();
            continue;
        };
        if let Some(info) = parse_dhcp(&buf[..n], xid, want) {
            return Some(info);
        }
        handle_frame(&buf[..n]);
    }
    None
}

fn handle_frame(frame: &[u8]) {
    if frame.len() < 14 {
        return;
    }
    let et = be16(frame, 12);
    if et == 0x0806 {
        handle_arp(frame);
    } else if et == 0x0800 {
        handle_ipv4(frame);
    }
}

fn handle_arp(frame: &[u8]) {
    if frame.len() < 42 {
        return;
    }
    let op = be16(frame, 20);
    let sha = [frame[22], frame[23], frame[24], frame[25], frame[26], frame[27]];
    let spa = be32(frame, 28);
    let tpa = be32(frame, 38);
    if op == 2 && spa != 0 {
        with_iface(|iface| arp_learn(iface, spa, sha));
    }
    let (mac, ip) = with_iface(|iface| (iface.mac, iface.ip));
    if op == 1 && ip != 0 && tpa == ip {
        let reply = build_arp(&mac, ip, spa, 2, &sha);
        let _ = crate::virtio_net::send_frame(&reply);
    }
}

fn handle_ipv4(frame: &[u8]) {
    if frame.len() < 14 + 20 {
        return;
    }
    let ihl = ((frame[14] & 0x0f) as usize) * 4;
    if ihl < 20 || frame.len() < 14 + ihl {
        return;
    }
    if internet_checksum(&frame[14..14 + ihl]) != 0 {
        return;
    }
    let proto = frame[14 + 9];
    if proto == 6 {
        handle_tcp(frame, ihl);
        return;
    }
    if proto != 17 {
        return;
    }
    let src = be32(frame, 14 + 12);
    let dst = be32(frame, 14 + 16);
    let udp = 14 + ihl;
    if frame.len() < udp + 8 {
        return;
    }
    let sport = be16(frame, udp);
    let dport = be16(frame, udp + 2);
    let ulen = be16(frame, udp + 4) as usize;
    if ulen < 8 || frame.len() < udp + ulen {
        return;
    }
    let ours = with_iface(|iface| iface.ip);
    if dst != ours && dst != 0xffff_ffff && !is_loopback(dst) {
        return;
    }
    if !udp_sum_ok(src, dst, &frame[udp..udp + ulen]) {
        return;
    }
    deliver(dst, dport, src, sport, &frame[udp + 8..udp + ulen]);
}

// ---- TCP на проводе ----
//
// Рукопожатие SYN/SYN-ACK/ACK, данные PSH|ACK строго по порядку (вне
// порядка — dupack), закрытие FIN|ACK. Повторов и окна на проводе нет:
// потерянный сегмент убивает передачу таймаутом читателя. Всё через ARP и
// gateway, как UDP.

const TH_FIN: u8 = 0x01;
const TH_SYN: u8 = 0x02;
const TH_RST: u8 = 0x04;
const TH_ACK: u8 = 0x10;
const TH_PSH: u8 = 0x08;

fn tcp_isn(id: usize) -> u32 {
    (crate::time::monotonic_ns() as u32)
        .wrapping_mul(0x9E37_79B1)
        .wrapping_add((id as u32).wrapping_mul(0x85EB_CA6B))
        | 1
}

/// Сумма TCP: псевдозаголовок + сегмент. Поле суммы в сегменте — 0.
fn tcp_checksum(src: u32, dst: u32, segment: &[u8]) -> u16 {
    let sum = finish_sum(pseudo_sum(src, dst, 6, segment.len()) + csum_add(0, segment));
    if sum == 0 {
        0xffff
    } else {
        sum
    }
}

fn build_tcp_frame(
    src_mac: &[u8; 6],
    dst_mac: &[u8; 6],
    src: u32,
    dst: u32,
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let tcp_len = 20 + payload.len();
    let total = 20 + tcp_len;
    let mut f = vec![0u8; 14 + total];
    f[0..6].copy_from_slice(dst_mac);
    f[6..12].copy_from_slice(src_mac);
    put_be16(&mut f, 12, 0x0800);
    f[14] = 0x45;
    put_be16(&mut f, 16, total as u16);
    put_be16(&mut f, 18, 1);
    f[22] = 64;
    f[23] = 6;
    put_be32(&mut f, 26, src);
    put_be32(&mut f, 30, dst);
    let sum = internet_checksum(&f[14..34]);
    put_be16(&mut f, 24, sum);
    let t = 34;
    put_be16(&mut f, t, sport);
    put_be16(&mut f, t + 2, dport);
    put_be32(&mut f, t + 4, seq);
    put_be32(&mut f, t + 8, ack);
    f[t + 12] = 0x50; // data offset 20 байт
    f[t + 13] = flags;
    put_be16(&mut f, t + 14, TCP_RX.min(65535) as u16); // window
    f[t + 16] = 0;
    f[t + 17] = 0; // urgent
    f[t + 20..t + 20 + payload.len()].copy_from_slice(payload);
    let csum = tcp_checksum(src, dst, &f[t..]);
    put_be16(&mut f, t + 16, csum);
    f
}

/// Отправить TCP-сегмент через ARP/gateway. Адрес источника `src` должен
/// быть уже решён (our_ip для клиента, адрес сокета для сервера).
fn send_tcp(src: u32, sport: u16, dst: u32, dport: u16, seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Result<(), i32> {
    let (mac, mask, gw) = with_iface(|iface| (iface.mac, iface.mask, iface.gw));
    let on_link = mask != 0 && (dst & mask) == (src & mask);
    let next = if on_link {
        arp_resolve(dst).map_err(|_| ENETDOWN)?
    } else if gw != 0 {
        arp_resolve(gw).map_err(|_| ENETDOWN)?
    } else {
        return Err(ENETDOWN);
    };
    let frame = build_tcp_frame(&mac, &next, src, dst, sport, dport, seq, ack, flags, payload);
    crate::virtio_net::send_frame(&frame).map_err(|_| EFAULT)?;
    Ok(())
}

/// Ответить RST несвоевременному сегменту (нет слушающего сокета).
fn tcp_rst(dst_ip: u32, dst_port: u16, src_ip: u32, src_port: u16, rx_seq: u32) {
    let src = our_ip();
    if src == 0 {
        return;
    }
    let _ = send_tcp(src, dst_port, src_ip, src_port, 0, rx_seq.wrapping_add(1), TH_RST | TH_ACK, &[]);
}

fn handle_tcp(frame: &[u8], ihl: usize) {
    let src = be32(frame, 14 + 12);
    let dst = be32(frame, 14 + 16);
    let t = 14 + ihl;
    if frame.len() < t + 20 {
        return;
    }
    let sport = be16(frame, t);
    let dport = be16(frame, t + 2);
    let rx_seq = be32(frame, t + 4);
    let rx_ack = be32(frame, t + 8);
    let data_off = ((frame[t + 12] >> 4) as usize) * 4;
    if data_off < 20 || frame.len() < t + data_off {
        return;
    }
    let flags = frame[t + 13];
    // Длина сегмента — из total_length IPv4: Ethernet-дополнение кадра
    // нулями не входит в TCP и портит контрольную сумму.
    let ip_total = be16(frame, 14 + 2) as usize;
    let seg_len = ip_total.saturating_sub(ihl);
    if seg_len < data_off || frame.len() < t + seg_len {
        return;
    }
    let payload = &frame[t + data_off..t + seg_len];
    // Сумма TCP обязательна (в отличие от UDP).
    if finish_sum(pseudo_sum(src, dst, 6, seg_len) + csum_add(0, &frame[t..])) != 0 {
        return;
    }
    let ours = with_iface(|iface| iface.ip);
    if dst != ours {
        return;
    }

    // SYN без ACK: новое соединение на слушающий порт.
    if flags & TH_SYN != 0 && flags & TH_ACK == 0 {
        with_tcp(|tab| {
            let lid = tab.iter().position(|s| {
                s.as_ref()
                    .map(|s| s.listen && s.port == dport && (s.addr == 0 || s.addr == dst))
                    .unwrap_or(false)
            });
            let Some(lid) = lid else {
                tcp_rst(src, sport, dst, dport, rx_seq);
                return;
            };
            let (limit, queued) = {
                let ls = tab[lid].as_ref().unwrap();
                (ls.backlog_max, ls.backlog.len())
            };
            let free = tab.iter().position(|s| s.is_none());
            let (Some(child), true) = (free, queued < limit) else {
                tcp_rst(src, sport, dst, dport, rx_seq);
                return;
            };
            let isn = tcp_isn(child);
            tab[child] = Some(TcpSock {
                refs: 1,
                listen: false,
                bound: true,
                wire: true,
                estab: false,
                seq: isn,
                rnext: rx_seq.wrapping_add(1),
                addr: dst,
                port: dport,
                peer_addr: src,
                peer_port: sport,
                peer: None,
                parent: Some(lid),
                backlog_max: 0,
                backlog: Vec::new(),
                rx: Vec::new(),
                eof: false,
                // Рождается блокирующим. SOCK_NONBLOCK ставит accept4, не слушатель.
                nonblock: false,
                unacked: Vec::new(),
                win: TCP_RX as u32,
                reorder: Vec::new(),
                reorder_fin: false,
                rtx: 0,
                cwnd: MSS,
                ssthresh: CWND_MAX,
                reuse: false,
                broadcast: false,
            });
            tab[lid].as_mut().unwrap().backlog.push(child);
            // SYN-ACK: seq = наш ISN, ack = их seq + 1.
            let _ = send_tcp(dst, dport, src, sport, isn, rx_seq.wrapping_add(1), TH_SYN | TH_ACK, &[]);
        });
        return;
    }

    // Остальное — по сокету (порт, адрес, порт пира).
    with_tcp(|tab| {
        let sid = tab.iter().position(|s| {
            s.as_ref()
                .map(|s| s.wire && s.port == dport && s.peer_addr == src && s.peer_port == sport)
                .unwrap_or(false)
        });
        let Some(sid) = sid else {
            if flags & TH_RST == 0 {
                tcp_rst(src, sport, dst, dport, rx_seq);
            }
            return;
        };
        let mut reply: Option<(u32, u32, u8, Vec<u8>)> = None;
        {
            let s = tab[sid].as_mut().unwrap();
            if flags & TH_RST != 0 {
                s.eof = true;
                s.estab = false;
            } else if flags & TH_SYN != 0 && flags & TH_ACK != 0 && !s.estab {
                // SYN-ACK на наш SYN клиента.
                if s.peer_addr == src && rx_ack == s.seq.wrapping_add(1) {
                    s.estab = true;
                    s.seq = s.seq.wrapping_add(1);
                    s.rnext = rx_seq.wrapping_add(1);
                    s.win = u32::from(be16(frame, t + 14));
                    reply = Some((s.seq, s.rnext, TH_ACK, Vec::new()));
                }
            } else if flags & TH_ACK != 0 && !s.estab {
                    // Третий шаг на SYN-Received дочернего сокета.
                if rx_ack == s.seq.wrapping_add(1) {
                    s.estab = true;
                    s.seq = s.seq.wrapping_add(1);
                    s.win = u32::from(be16(frame, t + 14));
                }
            } else if s.estab {
                // ACK: снимаем подтверждённое с inflight, запоминаем окно.
                if flags & TH_ACK != 0 {
                    s.win = u32::from(be16(frame, t + 14));
                    let before: u32 = s.unacked.iter().map(|(_, d, _)| d.len() as u32).sum();
                    s.unacked
                        .retain(|(sq, d, _)| rx_ack.wrapping_sub(*sq) < d.len() as u32);
                    let after: u32 = s.unacked.iter().map(|(_, d, _)| d.len() as u32).sum();
                    let acked = before.saturating_sub(after);
                    if acked > 0 {
                        if s.cwnd < s.ssthresh {
                            s.cwnd = s.cwnd.saturating_add(acked).min(CWND_MAX);
                        } else if s.cwnd > 0 {
                            s.cwnd = s.cwnd
                                .saturating_add(MSS.saturating_mul(MSS) / s.cwnd)
                                .min(CWND_MAX);
                        }
                    }
                    if s.unacked.is_empty() {
                        s.rtx = 0;
                    }
                }
                if rx_seq == s.rnext {
                    if !payload.is_empty() {
                        let space = TCP_RX.saturating_sub(s.rx.len());
                        let n = space.min(payload.len());
                        s.rx.extend_from_slice(&payload[..n]);
                        s.rnext = s.rnext.wrapping_add(n as u32);
                    }
                    // Закрыть дыру внеочередными сегментами, что накопились.
                    loop {
                        let hit = s
                            .reorder
                            .iter()
                            .position(|(sq, _)| *sq == s.rnext);
                        let Some(i) = hit else { break };
                        let (_, data) = s.reorder.remove(i);
                        let space = TCP_RX.saturating_sub(s.rx.len());
                        let n = space.min(data.len());
                        s.rx.extend_from_slice(&data[..n]);
                        s.rnext = s.rnext.wrapping_add(n as u32);
                    }
                    if s.reorder.is_empty() && s.reorder_fin {
                        // Дыра закрыта, ждущий FIN занимает следующий номер.
                        s.reorder_fin = false;
                        s.eof = true;
                        s.rnext = s.rnext.wrapping_add(1);
                    }
                    if flags & TH_FIN != 0 {
                        s.eof = true;
                        s.rnext = s.rnext.wrapping_add(1);
                    }
                    reply = Some((s.seq, s.rnext, TH_ACK, Vec::new()));
                } else {
                    // Вне очядь (или старый дубликат): прячем сегмент в
                    // reorder в пределах окна, просим дыру dupack'ом.
                    let ahead = rx_seq.wrapping_sub(s.rnext) as usize;
                    if flags & (TH_PSH | TH_FIN) != 0 && ahead > 0 {
                        let held: usize = s.reorder.iter().map(|(_, d)| d.len()).sum();
                        if held + payload.len() <= TCP_RX {
                            s.reorder.push((rx_seq, payload.to_vec()));
                        }
                        if flags & TH_FIN != 0 {
                            // FIN вне очереди: закроется, когда дыру дотянут.
                            s.reorder_fin = true;
                        }
                    }
                    reply = Some((s.seq, s.rnext, TH_ACK, Vec::new()));
                }
            }
        }
        if let Some((seq, ack, fl, data)) = reply {
            let (sport_o, dport_o, peer) = {
                let s = tab[sid].as_ref().unwrap();
                (s.port, s.peer_port, s.peer_addr)
            };
            let _ = send_tcp(dst, sport_o, peer, dport_o, seq, ack, fl, &data);
        }
    });
}

fn build_dhcp(mac: &[u8; 6], xid: u32, msg: u8, req_ip: u32, server: u32) -> Vec<u8> {
    let mut boot = [0u8; 300];
    boot[0] = 1;
    boot[1] = 1;
    boot[2] = 6;
    put_be32(&mut boot, 4, xid);
    put_be16(&mut boot, 10, 0x8000);
    boot[28..34].copy_from_slice(mac);
    boot[236..240].copy_from_slice(&[0x63, 0x82, 0x53, 0x63]);
    let mut n = 240;
    boot[n] = 53;
    boot[n + 1] = 1;
    boot[n + 2] = msg;
    n += 3;
    if msg == 3 {
        boot[n] = 50;
        boot[n + 1] = 4;
        put_be32(&mut boot, n + 2, req_ip);
        n += 6;
        if server != 0 {
            boot[n] = 54;
            boot[n + 1] = 4;
            put_be32(&mut boot, n + 2, server);
            n += 6;
        }
    }
    boot[n] = 55;
    boot[n + 1] = 3;
    boot[n + 2] = 1;
    boot[n + 3] = 3;
    boot[n + 4] = 6;
    n += 5;
    boot[n] = 255;
    n += 1;
    build_udp_frame(mac, &[0xff; 6], 0, 0xffff_ffff, 68, 67, &boot[..n])
}

fn parse_dhcp(frame: &[u8], xid: u32, want: u8) -> Option<DhcpInfo> {
    if frame.len() < 14 + 20 + 8 + 240 {
        return None;
    }
    if be16(frame, 12) != 0x0800 || frame[14 + 9] != 17 {
        return None;
    }
    let ihl = ((frame[14] & 0x0f) as usize) * 4;
    let udp = 14 + ihl;
    if frame.len() < udp + 8 + 240 {
        return None;
    }
    if be16(frame, udp) != 67 || be16(frame, udp + 2) != 68 {
        return None;
    }
    let p = udp + 8;
    if frame[p] != 2 || be32(frame, p + 4) != xid {
        return None;
    }
    if frame.get(p + 236..p + 240) != Some(&[0x63, 0x82, 0x53, 0x63][..]) {
        return None;
    }
    let yiaddr = be32(frame, p + 16);
    let opts = &frame[p + 240..];
    if dhcp_msg(opts) != Some(want) {
        return None;
    }
    Some(DhcpInfo {
        yiaddr,
        server: dhcp_opt_u32(opts, 54).unwrap_or(0),
        mask: dhcp_opt_u32(opts, 1).unwrap_or(0),
        gw: dhcp_opt_u32(opts, 3).unwrap_or(0),
    })
}

fn dhcp_msg(opts: &[u8]) -> Option<u8> {
    dhcp_opt(opts, 53).and_then(|v| v.first().copied())
}

fn dhcp_opt_u32(opts: &[u8], code: u8) -> Option<u32> {
    let v = dhcp_opt(opts, code)?;
    if v.len() < 4 {
        return None;
    }
    Some(u32::from_be_bytes([v[0], v[1], v[2], v[3]]))
}

fn dhcp_opt<'a>(opts: &'a [u8], code: u8) -> Option<&'a [u8]> {
    let mut i = 0;
    while i < opts.len() {
        let c = opts[i];
        if c == 255 {
            break;
        }
        if c == 0 {
            i += 1;
            continue;
        }
        if i + 1 >= opts.len() {
            break;
        }
        let len = opts[i + 1] as usize;
        if i + 2 + len > opts.len() {
            break;
        }
        if c == code {
            return Some(&opts[i + 2..i + 2 + len]);
        }
        i += 2 + len;
    }
    None
}

fn build_arp(src_mac: &[u8; 6], spa: u32, tpa: u32, op: u16, dst_mac: &[u8; 6]) -> Vec<u8> {
    let mut f = vec![0u8; 42];
    if op == 1 {
        f[0..6].copy_from_slice(&[0xff; 6]);
    } else {
        f[0..6].copy_from_slice(dst_mac);
    }
    f[6..12].copy_from_slice(src_mac);
    put_be16(&mut f, 12, 0x0806);
    put_be16(&mut f, 14, 1);
    put_be16(&mut f, 16, 0x0800);
    f[18] = 6;
    f[19] = 4;
    put_be16(&mut f, 20, op);
    f[22..28].copy_from_slice(src_mac);
    put_be32(&mut f, 28, spa);
    if op == 2 {
        f[32..38].copy_from_slice(dst_mac);
    }
    put_be32(&mut f, 38, tpa);
    f
}

fn build_udp_frame(
    src_mac: &[u8; 6],
    dst_mac: &[u8; 6],
    src: u32,
    dst: u32,
    sport: u16,
    dport: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let total = 20 + udp_len;
    let mut f = vec![0u8; 14 + total];
    f[0..6].copy_from_slice(dst_mac);
    f[6..12].copy_from_slice(src_mac);
    put_be16(&mut f, 12, 0x0800);
    f[14] = 0x45;
    put_be16(&mut f, 16, total as u16);
    put_be16(&mut f, 18, 1);
    f[22] = 64;
    f[23] = 17;
    put_be32(&mut f, 26, src);
    put_be32(&mut f, 30, dst);
    let sum = internet_checksum(&f[14..34]);
    put_be16(&mut f, 24, sum);
    put_be16(&mut f, 34, sport);
    put_be16(&mut f, 36, dport);
    put_be16(&mut f, 38, udp_len as u16);
    f[42..42 + payload.len()].copy_from_slice(payload);
    let udp_sum = udp_checksum(src, dst, &f[34..]);
    put_be16(&mut f, 40, udp_sum);
    f
}

/// Сумма UDP вместе с псевдозаголовком. Поле суммы в `segment` должно быть 0.
/// Результат 0 заменяется на 0xFFFF: ноль в кадре значит «суммы нет».
fn udp_checksum(src: u32, dst: u32, segment: &[u8]) -> u16 {
    let sum = finish_sum(pseudo_sum(src, dst, 17, segment.len()) + csum_add(0, segment));
    if sum == 0 {
        0xffff
    } else {
        sum
    }
}

/// `true`, если сумма 0 (IPv4: не считали) или сошлась.
fn udp_sum_ok(src: u32, dst: u32, segment: &[u8]) -> bool {
    if segment.len() < 8 {
        return false;
    }
    let field = u16::from_be_bytes([segment[6], segment[7]]);
    if field == 0 {
        return true;
    }
    finish_sum(pseudo_sum(src, dst, 17, segment.len()) + csum_add(0, segment)) == 0
}

fn pseudo_sum(src: u32, dst: u32, proto: u32, len: usize) -> u32 {
    let mut sum = 0u32;
    sum += (src >> 16) as u32;
    sum += (src & 0xffff) as u32;
    sum += (dst >> 16) as u32;
    sum += (dst & 0xffff) as u32;
    sum += proto;
    sum += len as u32;
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

/// Сумма RFC 1071. Для исходящего заголовка поле контрольной суммы — нули.
/// Для входящего заголовка результат 0 значит «сошлась».
pub fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn be16(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}
fn be32(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}
fn put_be16(b: &mut [u8], at: usize, v: u16) {
    b[at..at + 2].copy_from_slice(&v.to_be_bytes());
}
fn put_be32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_be_bytes());
}

const TCP_N: usize = 16;
const TCP_RX: usize = 8192;

struct TcpSock {
    refs: u8,
    listen: bool,
    bound: bool,
    nonblock: bool,
    /// Соединение через провод (wire TCP): SYN/SYN-ACK, seq/ack, FIN.
    wire: bool,
    /// Рукопожатие завершено (wire) или петля соединена.
    estab: bool,
    /// Следующий TX seq (wire) / ISN+1 после SYN.
    seq: u32,
    /// Следующий ожидаемый RX seq (wire).
    rnext: u32,
    addr: u32,
    port: u16,
    peer_addr: u32,
    peer_port: u16,
    peer: Option<usize>,
    parent: Option<usize>,
    backlog_max: usize,
    backlog: Vec<usize>,
    rx: Vec<u8>,
    eof: bool,
    /// Провод: неподтверждённые исходящие сегменты (seq, данные, когда
    /// отправлены в последний раз). Пусто у сокетов петли.
    unacked: Vec<(u32, Vec<u8>, u64)>,
    /// Скользящее окно пира из последнего ACK (наш приём — TCP_RX).
    win: u32,
    /// Провод: внеочередные сегменты (seq > rnext), ждут закрытия дыры.
    reorder: Vec<(u32, Vec<u8>)>,
    /// FIN пришёл вне очереди: eof ставим, когда дыру дотянут.
    reorder_fin: bool,
    /// Счётчик ретрансмиссий: за пределами — разрыв (eof).
    rtx: u8,
    /// Окно перегрузки и порог медленного старта. Петля их не смотрит.
    cwnd: u32,
    ssthresh: u32,
    /// `SO_REUSEADDR`: два слушающих сокета делят порт, если флаг у обоих.
    reuse: bool,
    /// `SO_BROADCAST`. У TCP не на что влиять, но getsockopt обязан вернуть то, что записали.
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
        wire: false,
        estab: false,
        seq: 0,
        rnext: 0,
        addr: 0,
        port: 0,
        peer_addr: 0,
        peer_port: 0,
        peer: None,
        parent: None,
        backlog_max: 0,
        backlog: Vec::new(),
        rx: Vec::new(),
        eof: false,
        unacked: Vec::new(),
        win: TCP_RX as u32,
        reorder: Vec::new(),
        reorder_fin: false,
        rtx: 0,
        cwnd: MSS,
        ssthresh: CWND_MAX,
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

pub fn tcp_nonblock(id: usize) -> bool {
    with_tcp(|tab| {
        tab.get(id)
            .and_then(|s| s.as_ref())
            .map(|s| s.nonblock)
            .unwrap_or(false)
    })
}

/// `accept4` ставит `SOCK_NONBLOCK` уже принятому сокету. Слушатель не копируется.
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

fn tcp_drop(tab: &mut [Option<TcpSock>; TCP_N], id: usize) {
    let Some(Some(s)) = tab.get_mut(id) else {
        return;
    };
    s.refs = s.refs.saturating_sub(1);
    if s.refs > 0 {
        return;
    }
    let sock = tab[id].take().unwrap();
    // Закрытие живого проводного соединения — FIN|ACK, пир увидит EOF.
    if sock.wire && sock.estab && !sock.eof && !sock.listen {
        let _ = send_tcp(sock.addr, sock.port, sock.peer_addr, sock.peer_port, sock.seq, sock.rnext, TH_ACK | TH_FIN, &[]);
    }
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

pub fn tcp_close(id: usize) {
    with_tcp(|tab| tcp_drop(tab, id));
}

pub fn tcp_bind(id: usize, addr: u32, port: u16) -> Result<(), i32> {
    if !addr_ok(addr) {
        return Err(EADDRNOTAVAIL);
    }
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

pub fn tcp_accept(id: usize) -> Result<(usize, u32, u16), i32> {
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

/// Проводное соединение: SYN, ожидание SYN-ACK с pump (до 3 попыток),
/// blocking-до-установления или EINPROGRESS у неблокирующего сокета.
/// RST от пира — ECONNREFUSED. Данные после установки повторяются по RTO.
fn tcp_connect_wire(id: usize, dst_ip: u32, dst_port: u16) -> Result<(), i32> {
    let ip = our_ip();
    if ip == 0 || !crate::virtio_net::present() {
        return Err(ENETUNREACH);
    }
    // Подготовка сокета: порт, ISN, пир. Повторный connect на том же
    // сокете продолжает ждать того же хендшейка (как EALREADY, но молча).
    let (isn, nonblock, _started) = with_tcp(|tab| {
        // Порт — иммутабельным проходом по таблице, мутация сокета — после:
        // tcp_alloc_port(tab) не дружит с живым &mut на слот.
        let need_port = match tab.get(id).and_then(|s| s.as_ref()) {
            None => return Err(EFAULT),
            Some(s) if s.listen => return Err(EINVAL),
            Some(s) if s.estab => return Err(EISCONN),
            Some(s) if s.seq != 0 => return Ok((s.seq, s.nonblock, true)),
            Some(s) => !(s.bound && s.port != 0),
        };
        let port = if need_port {
            let p = tcp_alloc_port(tab);
            if p == 0 {
                return Err(EADDRINUSE);
            }
            p
        } else {
            tab[id].as_ref().unwrap().port
        };
        let s = tab[id].as_mut().unwrap();
        if need_port {
            s.port = port;
            s.bound = true;
        }
        let isn = tcp_isn(id);
        s.wire = true;
        s.addr = ip;
        s.seq = isn;
        s.peer_addr = dst_ip;
        s.peer_port = dst_port;
        Ok((isn, s.nonblock, false))
    })?;
    if nonblock {
        let estab = with_tcp(|tab| {
            tab.get(id)
                .and_then(|s| s.as_ref())
                .map(|s| s.estab)
                .unwrap_or(false)
        });
        if estab {
            return Ok(());
        }
        // SYN уйдёт сейчас; завершится читателем/поллером или повторным connect.
        let _ = send_tcp(ip, wire_port(id)?, dst_ip, dst_port, isn, 0, TH_SYN, &[]);
        return Err(EINPROGRESS);
    }
    for _attempt in 0..3 {
        {
            let sport = wire_port(id)?;
            send_tcp(ip, sport, dst_ip, dst_port, isn, 0, TH_SYN, &[])?;
        }
        let deadline = crate::time::monotonic_ns().saturating_add(2_500_000_000);
        while crate::time::monotonic_ns() < deadline {
            pump();
            let (estab, dead) = with_tcp(|tab| {
                tab.get(id)
                    .and_then(|s| s.as_ref())
                    .map(|s| (s.estab, s.eof))
                    .unwrap_or((false, true))
            });
            if estab {
                return Ok(());
            }
            if dead {
                return Err(ECONNREFUSED);
            }
            if crate::signal::pending_interrupts() {
                return Err(EINTR);
            }
            core::hint::spin_loop();
        }
    }
    Err(ETIMEDOUT)
}

fn wire_port(id: usize) -> Result<u16, i32> {
    with_tcp(|tab| {
        tab.get(id)
            .and_then(|s| s.as_ref())
            .filter(|s| s.bound)
            .map(|s| s.port)
            .ok_or(EFAULT)
    })
}

pub fn tcp_connect(id: usize, dst_ip: u32, dst_port: u16) -> Result<(), i32> {
    if dst_port == 0 || dst_ip == 0 {
        return Err(EINVAL);
    }
    if !is_loopback(dst_ip) {
        return tcp_connect_wire(id, dst_ip, dst_port);
    }
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
                .map(|s| s.listen && s.port == dst_port && (s.addr == 0 || s.addr == dst_ip))
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
            let local = if ls.addr == 0 { dst_ip } else { ls.addr };
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
            // Рождается блокирующим. SOCK_NONBLOCK ставит accept4, не слушатель.
            nonblock: false,
            wire: false,
            estab: true,
            seq: 0,
            rnext: 0,
            addr: local,
            port: dst_port,
            peer_addr: 0x7f00_0001,
            peer_port: cport,
            peer: Some(id),
            parent: Some(lid),
            backlog_max: 0,
            backlog: Vec::new(),
            rx: Vec::new(),
            eof: false,
            unacked: Vec::new(),
            win: TCP_RX as u32,
            reorder: Vec::new(),
            reorder_fin: false,
            rtx: 0,
            cwnd: MSS,
            ssthresh: CWND_MAX,
            reuse: false,
            broadcast: false,
        });
        {
            let s = tab[id].as_mut().unwrap();
            s.bound = true;
            s.addr = 0x7f00_0001;
            s.port = cport;
            s.peer_addr = dst_ip;
            s.peer_port = dst_port;
            s.peer = Some(child);
            s.estab = true;
            s.eof = false;
        }
        tab[lid].as_mut().unwrap().backlog.push(child);
        Ok(())
    })
}

pub fn tcp_name(id: usize) -> Option<(u32, u16)> {
    with_tcp(|tab| {
        tab.get(id)
            .and_then(|s| s.as_ref())
            .filter(|s| s.bound)
            .map(|s| (s.addr, s.port))
    })
}

pub fn tcp_peer(id: usize) -> Option<(u32, u16)> {
    with_tcp(|tab| {
        tab.get(id).and_then(|s| s.as_ref()).and_then(|s| {
            // Проводной сокет знает пира сразу после connect/accept.
            if s.peer.is_some() || s.wire || s.eof {
                Some((s.peer_addr, s.peer_port))
            } else {
                None
            }
        })
    })
}

pub fn tcp_send(id: usize, data: &[u8]) -> Result<usize, i32> {
    if data.is_empty() {
        return Ok(0);
    }
    with_tcp(|tab| {
        let (listen, wire, estab, eof) = {
            let Some(s) = tab.get(id).and_then(|s| s.as_ref()) else {
                return Err(EFAULT);
            };
            (s.listen, s.wire, s.estab, s.eof)
        };
        if listen {
            return Err(ENOTCONN);
        }
        if wire {
            // Провод: PSH|ACK в пределах окна пира. Неподтверждённое копится
            // в unacked — pump() повторяет по таймауту, пока ACK не догонит.
            if eof {
                return Err(EPIPE);
            }
            if !estab {
                return Err(ENOTCONN);
            }
            let now = crate::time::monotonic_ns();
            let s = tab[id].as_mut().unwrap();
            let inflight: u32 = s.unacked.iter().map(|(_, d, _)| d.len() as u32).sum();
            if s.win == 0 {
                // Нулевое окно: ждём window update (пока — EAGAIN).
                return Err(EAGAIN);
            }
            let budget = s.win.min(s.cwnd);
            let avail = budget.saturating_sub(inflight) as usize;
            let n = data.len().min(MSS as usize).min(avail);
            if n == 0 {
                return Err(EAGAIN);
            }
            let seq = s.seq;
            let r = send_tcp(s.addr, s.port, s.peer_addr, s.peer_port, seq, s.rnext, TH_ACK | TH_PSH, &data[..n]);
            match r {
                Ok(()) => {
                    s.seq = s.seq.wrapping_add(n as u32);
                    s.unacked.push((seq, data[..n].to_vec(), now));
                    Ok(n)
                }
                Err(e) => Err(e),
            }
        } else {
            let peer = tab.get(id).and_then(|s| s.as_ref()).and_then(|s| s.peer);
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
        }
    })
}

pub fn tcp_recv(id: usize, buf: &mut [u8]) -> Result<(usize, u32, u16), i32> {
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
            // Проводной установленный сокет пиром в таблице не является:
            // ждём данные с провода (EAGAIN), а не ENOTCONN.
            let waiting = s.peer.is_some() || (s.wire && s.estab);
            return Err(if waiting { EAGAIN } else { ENOTCONN });
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
    fn ipv4_header_checksum() {
        serial_print!("test ipv4_header_checksum... ");
        let mut hdr = [
            0x45u8, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0xac, 0x10,
            0x0a, 0x63, 0xac, 0x10, 0x0a, 0x0c,
        ];
        let sum = internet_checksum(&hdr);
        assert_eq!(sum, 0xb1e6, "sum {:#x}", sum);
        hdr[10] = 0xb1;
        hdr[11] = 0xe6;
        assert_eq!(internet_checksum(&hdr), 0);
        serial_println!("[ok]");
    }

    #[test_case]
    fn udp_checksum_rejects_a_bad_wire_sum() {
        serial_print!("test udp_checksum_rejects_a_bad_wire_sum... ");
        let mac = [2u8, 0, 0, 0, 0, 1];
        let frame = build_udp_frame(&mac, &mac, 0x0a00_020f, 0x0a00_0202, 1234, 53, b"hi");
        let segment = &frame[34..];
        assert_ne!(u16::from_be_bytes([segment[6], segment[7]]), 0);
        assert!(udp_sum_ok(0x0a00_020f, 0x0a00_0202, segment));
        let mut bad = frame.clone();
        bad[42] ^= 0xff;
        assert!(!udp_sum_ok(0x0a00_020f, 0x0a00_0202, &bad[34..]));
        let mut open = frame.clone();
        open[40] = 0;
        open[41] = 0;
        open[42] ^= 0xff;
        assert!(udp_sum_ok(0x0a00_020f, 0x0a00_0202, &open[34..]));
        serial_println!("[ok]");
    }

    #[test_case]
    fn arp_table_keeps_eight_then_evicts() {
        serial_print!("test arp_table_keeps_eight_then_evicts... ");
        let mut iface = Iface {
            mac: [0; 6],
            up: false,
            ip: 0,
            mask: 0,
            gw: 0,
            arp: [ArpSlot { ip: 0, mac: [0; 6] }; ARP_SLOTS],
            arp_hand: 0,
        };
        for i in 1..=8u32 {
            arp_learn(&mut iface, i, [i as u8, 0, 0, 0, 0, 1]);
        }
        assert_eq!(arp_find(&iface, 1).map(|m| m[0]), Some(1));
        assert_eq!(arp_find(&iface, 8).map(|m| m[0]), Some(8));
        arp_learn(&mut iface, 9, [9, 0, 0, 0, 0, 1]);
        assert!(arp_find(&iface, 1).is_none());
        assert_eq!(arp_find(&iface, 2).map(|m| m[0]), Some(2));
        assert_eq!(arp_find(&iface, 9).map(|m| m[0]), Some(9));
        arp_learn(&mut iface, 9, [9, 1, 0, 0, 0, 2]);
        assert_eq!(arp_find(&iface, 9).map(|m| m[0]), Some(9));
        assert_eq!(arp_find(&iface, 2).map(|m| m[0]), Some(2));
        serial_println!("[ok]");
    }

    #[test_case]
    fn udp_loopback_roundtrip() {
        serial_print!("test udp_loopback_roundtrip... ");
        let a = udp_open(true).expect("open");
        udp_bind(a, 0x7f00_0001, 19000).expect("bind");
        let b = udp_open(true).expect("open b");
        let err = udp_bind(b, 0, 19000).expect_err("second bind");
        assert_eq!(err, EADDRINUSE);
        udp_close(b);
        let n = udp_send(a, b"rudra-udp", Some((0x7f00_0001, 19000))).expect("send");
        assert_eq!(n, 9);
        let mut buf = [0u8; 32];
        let (rn, src, port) = udp_recv(a, &mut buf).expect("recv");
        assert_eq!(rn, 9);
        assert_eq!(&buf[..9], b"rudra-udp");
        assert_eq!(src, 0x7f00_0001);
        assert_eq!(port, 19000);
        udp_close(a);
        serial_println!("[ok]");
    }

    #[test_case]
    fn tcp_loopback_moves_bytes_and_refuses_the_wire() {
        serial_print!("test tcp_loopback_moves_bytes_and_refuses_the_wire... ");
        let listener = tcp_open(true).expect("listen open");
        tcp_bind(listener, 0x7f00_0001, 19001).expect("bind");
        tcp_listen(listener, 2).expect("listen");
        let client = tcp_open(true).expect("client");
        // Проводной connect: без адреса на карте — ENETUNREACH; если DHCP
        // уже поднят (сетевой тест выше), хост отвечает RST — ECONNREFUSED
        // или молчит до таймаута. Всё — честный исход попытки на провод.
        let err = tcp_connect(client, 0x0a00_0202, 19001).expect_err("wire");
        assert!(
            matches!(err, ENETUNREACH | ECONNREFUSED | ETIMEDOUT | EINPROGRESS),
            "wire connect: {err}"
        );
        // Сокет после неудачного wire-connect чист для петли: seq не выдан.
        let client2 = tcp_open(true).expect("client2");
        assert_eq!(
            tcp_connect(client2, 0x7f00_0001, 9).expect_err("closed"),
            ECONNREFUSED
        );
        tcp_connect(client2, 0x7f00_0001, 19001).expect("connect");
        let (accepted, src, sport) = tcp_accept(listener).expect("accept");
        assert_eq!(src, 0x7f00_0001);
        assert_ne!(sport, 0);
        let n = tcp_send(client2, b"ping").expect("send");
        assert_eq!(n, 4);
        let mut buf = [0u8; 8];
        let (rn, _, _) = tcp_recv(accepted, &mut buf).expect("recv");
        assert_eq!(&buf[..rn], b"ping");
        tcp_send(accepted, b"pong").expect("reply");
        let (rn, _, _) = tcp_recv(client2, &mut buf).expect("reply recv");
        assert_eq!(&buf[..rn], b"pong");
        tcp_close(client2);
        let (rn, _, _) = tcp_recv(accepted, &mut buf).expect("eof");
        assert_eq!(rn, 0);
        tcp_close(accepted);
        tcp_close(listener);
        serial_println!("[ok]");
    }

    #[test_case]
    fn accepted_tcp_starts_blocking_until_the_flag_is_set() {
        serial_print!("test accepted_tcp_starts_blocking_until_the_flag_is_set... ");
        let listener = tcp_open(true).expect("listen");
        tcp_bind(listener, 0x7f00_0001, 19002).expect("bind");
        tcp_listen(listener, 1).expect("listen");
        let client = tcp_open(true).expect("client");
        tcp_connect(client, 0x7f00_0001, 19002).expect("connect");
        let (child, _, _) = tcp_accept(listener).expect("accept");
        // Слушатель неблокирующий, ребёнок всё равно рождается блокирующим.
        assert!(tcp_nonblock(listener));
        assert!(!tcp_nonblock(child));
        tcp_set_nonblock(child, true).expect("set");
        assert!(tcp_nonblock(child));
        tcp_set_nonblock(child, false).expect("clear");
        assert!(!tcp_nonblock(child));
        assert_eq!(tcp_set_nonblock(TCP_N, true).expect_err("missing"), EFAULT);
        tcp_close(child);
        tcp_close(client);
        tcp_close(listener);
        serial_println!("[ok]");
    }

    #[test_case]
    fn udp_remembers_reuse_and_broadcast() {
        serial_print!("test udp_remembers_reuse_and_broadcast... ");
        let a = udp_open(true).expect("open");
        udp_set_opt(a, 2, true).expect("reuse");
        udp_set_opt(a, 6, true).expect("bcast");
        assert_eq!(udp_get_opt(a, 2).expect("get"), 1);
        assert_eq!(udp_get_opt(a, 6).expect("get b"), 1);
        udp_bind(a, 0x7f00_0001, 19020).expect("bind");
        let b = udp_open(true).expect("open b");
        assert_eq!(udp_bind(b, 0x7f00_0001, 19020).expect_err("busy"), EADDRINUSE);
        udp_set_opt(b, 2, true).expect("reuse b");
        udp_bind(b, 0x7f00_0001, 19020).expect("share");
        let c = udp_open(true).expect("open c");
        assert_eq!(
            udp_send(c, b"x", Some((0xffff_ffff, 9))).expect_err("bcast"),
            EACCES
        );
        udp_set_opt(c, 6, true).expect("allow");
        // Флаг снят: в провод можно (или карта ответит своей ошибкой), но не EACCES.
        if let Err(err) = udp_send(c, b"x", Some((0xffff_ffff, 9))) {
            assert_ne!(err, EACCES);
        }
        udp_close(a);
        udp_close(b);
        udp_close(c);
        serial_println!("[ok]");
    }

    #[test_case]
    fn dhcp_and_gateway_arp() {
        serial_print!("test dhcp_and_gateway_arp... ");
        assert!(crate::virtio_net::present(), "virtio-net missing");
        let ip = dhcp().expect("dhcp");
        assert_eq!(ip & 0xffff_ff00, 0x0a00_0200, "ip {:#x}", ip);
        let gw = gateway();
        assert_ne!(gw, 0);
        let mac = arp_resolve(gw).expect("arp");
        assert_ne!(mac, [0u8; 6]);
        serial_println!(
            "[ok] ip {}.{}.{}.{} gw-mac {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            ip >> 24,
            (ip >> 16) & 255,
            (ip >> 8) & 255,
            ip & 255,
            mac[0],
            mac[1],
            mac[2],
            mac[3],
            mac[4],
            mac[5]
        );
    }
}
