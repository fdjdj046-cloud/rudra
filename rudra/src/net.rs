//! IPv4 и UDP. Петля `127.0.0.0/8` живёт без карты.
//! В провод уходит кадр через virtio-net: ARP на восемь соседей и DHCP.
//! Исходящий UDP считает сумму. Входящая сумма 0 на IPv4 значит «не считали»
//! и принимается: так QEMU отдаёт DHCP. IPv6, TCP и netlink здесь нет.

use alloc::vec;
use alloc::vec::Vec;
use spin::Mutex;

const SOCKS: usize = 16;
const QLEN: usize = 4;
const DGRAM_MAX: usize = 1280;

pub const EAGAIN: i32 = 11;
pub const EFAULT: i32 = 14;
pub const EINVAL: i32 = 22;
pub const ENFILE: i32 = 23;
pub const EDESTADDRREQ: i32 = 89;
pub const EMSGSIZE: i32 = 90;
pub const EADDRINUSE: i32 = 98;
pub const EADDRNOTAVAIL: i32 = 99;
pub const ENETDOWN: i32 = 100;

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
        }
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
    let (src, sport, dest) = with_socks(|tab| -> Result<_, i32> {
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
        Ok((src, s.port, dest))
    })?;
    let src = if src != 0 { src } else { our_ip() };
    if is_loopback(dest.0) || (src != 0 && dest.0 == src) {
        deliver(dest.0, dest.1, src, sport, data);
        return Ok(data.len());
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
    tab.iter().enumerate().any(|(i, s)| {
        i != except && s.as_ref().map(|s| s.bound && s.port == port).unwrap_or(false)
    })
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
    if frame[14 + 9] != 17 {
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
    let sum = finish_sum(pseudo_sum(src, dst, segment.len()) + csum_add(0, segment));
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
    finish_sum(pseudo_sum(src, dst, segment.len()) + csum_add(0, segment)) == 0
}

fn pseudo_sum(src: u32, dst: u32, udp_len: usize) -> u32 {
    let mut sum = 0u32;
    sum += (src >> 16) as u32;
    sum += (src & 0xffff) as u32;
    sum += (dst >> 16) as u32;
    sum += (dst & 0xffff) as u32;
    sum += 17;
    sum += udp_len as u32;
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
