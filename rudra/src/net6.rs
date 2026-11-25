//! IPv6: петля `::1` и link-local на одной карте.
//!
//! `::1` копирует байты в памяти и кадр не строит. `fe80::/10` — адрес EUI-64
//! MAC virtio, сосед находится NDP (NS/NA), кэш на восемь записей. UDP и TCP
//! уходят только такому соседу. Глобальный адрес, SLAAC, DHCPv6 и
//! маршрутизатор отсутствуют. Netlink этот модуль не обслуживает.
//! IPv4-mapped (`::ffff:0:0/96`) — `EAFNOSUPPORT`.
//!
//! Сумма верхнего уровня считается по RFC 8200. На петле она в кадр не
//! вкладывается. Ноль у UDP — не «суммы нет», в отличие от IPv4. NDP требует
//! hop limit 255. Свой MAC в multicast-фильтр карты не пишется: без control
//! queue QEMU и так отдаёт solicited-node.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
#[cfg(test)]
use core::sync::atomic::AtomicUsize;
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
pub const ENETDOWN: i32 = 100;
pub const ENETUNREACH: i32 = 101;
pub const EISCONN: i32 = 106;
pub const ENOTCONN: i32 = 107;
pub const ECONNREFUSED: i32 = 111;
pub const ETIMEDOUT: i32 = 110;
pub const EINPROGRESS: i32 = 115;
pub const EINTR: i32 = 4;
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

/// `fe80::/10`: первый байт `0xfe`, старшие два бита второго — `10`.
fn is_link_local(addr: &[u8; 16]) -> bool {
    addr[0] == 0xfe && addr[1] & 0xc0 == 0x80
}

fn check_local(addr: &[u8; 16]) -> Result<(), i32> {
    if is_v4mapped(addr) {
        return Err(EAFNOSUPPORT);
    }
    if is_unspec(addr) || is_loopback(addr) {
        return Ok(());
    }
    let ll = our_ll();
    if ll != UNSPEC && *addr == ll {
        return Ok(());
    }
    Err(EADDRNOTAVAIL)
}

fn check_dest(addr: &[u8; 16], port: u16) -> Result<(), i32> {
    if port == 0 || is_unspec(addr) {
        return Err(EINVAL);
    }
    if is_v4mapped(addr) {
        return Err(EAFNOSUPPORT);
    }
    if is_loopback(addr) || is_link_local(addr) {
        return Ok(());
    }
    Err(ENETUNREACH)
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

// ---- link-local и NDP ----
//
// Один адрес `fe80::/64` из MAC. Сосед — только `fe80::/10`, кэш как ARP.
// RA, RS, redirect и DAD не обрабатываются: чужой NS с источником `::`
// молча отбрасывается. Кадр уходит в карту, а в тесте — в очередь захвата,
// чтобы проверка не зависела от того, ответит ли SLIRP.

const ND_SLOTS: usize = 8;
const WIRE_DGRAM_MAX: usize = 1452;
const HOP_LIMIT: u8 = 64;
const HOP_NDP: u8 = 255;

const TH_FIN: u8 = 0x01;
const TH_SYN: u8 = 0x02;
const TH_RST: u8 = 0x04;
const TH_PSH: u8 = 0x08;
const TH_ACK: u8 = 0x10;

const RTO_NS: u64 = 500_000_000;
const RTO_TC: u8 = 8;
const MSS: u32 = 1280;
const CWND_MAX: u32 = 64 * 1024;

#[derive(Clone, Copy)]
struct NdSlot {
    ip: [u8; 16],
    mac: [u8; 6],
}

struct Link {
    up: bool,
    mac: [u8; 6],
    ll: [u8; 16],
    nd: [NdSlot; ND_SLOTS],
    hand: usize,
}

static LINK: Mutex<Link> = Mutex::new(Link {
    up: false,
    mac: [0; 6],
    ll: UNSPEC,
    nd: [NdSlot {
        ip: UNSPEC,
        mac: [0; 6],
    }; ND_SLOTS],
    hand: 0,
});

/// Тест подменяет карту. В бою здесь `None`, кадр уходит в virtio.
static TX: Mutex<Option<Vec<Vec<u8>>>> = Mutex::new(None);
static ND_BUSY: AtomicBool = AtomicBool::new(false);
/// Пока удержан, тик таймера не забирает повтор. Принудительный вызов теста — да.
#[cfg(test)]
static RTX_HOLD: AtomicBool = AtomicBool::new(false);
/// Сколько входов `retransmit` уже прошли проверку удержания.
#[cfg(test)]
static RTX_DEPTH: AtomicUsize = AtomicUsize::new(0);
/// Истина только на время `retransmit_forced`: удержание его не глушит.
#[cfg(test)]
static RTX_FORCE: AtomicBool = AtomicBool::new(false);

struct NdGuard;
impl Drop for NdGuard {
    fn drop(&mut self) {
        ND_BUSY.store(false, Ordering::SeqCst);
    }
}

fn with_link<R>(f: impl FnOnce(&mut Link) -> R) -> R {
    x86_64::instructions::interrupts::without_interrupts(|| f(&mut LINK.lock()))
}

/// Поднять link-local по MAC. Повтор с тем же MAC кэш не трогает только если
/// адрес совпал: чужой MAC (тест) сбрасывает соседей.
pub fn attach(mac: [u8; 6]) {
    let ll = eui64(&mac);
    with_link(|link| {
        if link.up && link.mac == mac && link.ll == ll {
            return;
        }
        link.up = true;
        link.mac = mac;
        link.ll = ll;
        link.nd = [NdSlot {
            ip: UNSPEC,
            mac: [0; 6],
        }; ND_SLOTS];
        link.hand = 0;
    });
}

fn our_ll() -> [u8; 16] {
    with_link(|link| if link.up { link.ll } else { UNSPEC })
}

/// Снимок link-local для дампа netlink. Выключенная карта — нулевой адрес.
#[derive(Clone, Copy)]
pub struct LlSnap {
    pub up: bool,
    pub mac: [u8; 6],
    pub ll: [u8; 16],
}

pub fn ll_snap() -> LlSnap {
    with_link(|link| LlSnap {
        up: link.up,
        mac: link.mac,
        ll: if link.up { link.ll } else { UNSPEC },
    })
}

fn identity() -> Result<([u8; 6], [u8; 16]), i32> {
    with_link(|link| {
        if link.up {
            Ok((link.mac, link.ll))
        } else {
            Err(ENETDOWN)
        }
    })
}

/// IID: инверсия U/L у первого октета MAC и `ff:fe` посередине.
fn eui64(mac: &[u8; 6]) -> [u8; 16] {
    let mut a = [0u8; 16];
    a[0] = 0xfe;
    a[1] = 0x80;
    a[8] = mac[0] ^ 0x02;
    a[9] = mac[1];
    a[10] = mac[2];
    a[11] = 0xff;
    a[12] = 0xfe;
    a[13] = mac[3];
    a[14] = mac[4];
    a[15] = mac[5];
    a
}

fn solicited_node(addr: &[u8; 16]) -> [u8; 16] {
    let mut a = [0u8; 16];
    a[0] = 0xff;
    a[1] = 0x02;
    a[11] = 0x01;
    a[12] = 0xff;
    a[13] = addr[13];
    a[14] = addr[14];
    a[15] = addr[15];
    a
}

fn multicast_mac(addr: &[u8; 16]) -> [u8; 6] {
    [0x33, 0x33, addr[12], addr[13], addr[14], addr[15]]
}

fn nd_cached(ip: &[u8; 16]) -> Option<[u8; 6]> {
    with_link(|link| {
        link.nd
            .iter()
            .find(|s| s.ip == *ip && s.mac != [0; 6])
            .map(|s| s.mac)
    })
}

fn nd_learn(ip: [u8; 16], mac: [u8; 6]) {
    if !is_link_local(&ip) || mac == [0; 6] {
        return;
    }
    with_link(|link| {
        if let Some(slot) = link.nd.iter_mut().find(|s| s.ip == ip) {
            slot.mac = mac;
            return;
        }
        if let Some(slot) = link.nd.iter_mut().find(|s| s.ip == UNSPEC) {
            *slot = NdSlot { ip, mac };
            return;
        }
        let hand = link.hand % ND_SLOTS;
        link.nd[hand] = NdSlot { ip, mac };
        link.hand = (hand + 1) % ND_SLOTS;
    });
}

fn capture_on() -> bool {
    x86_64::instructions::interrupts::without_interrupts(|| TX.lock().is_some())
}

#[cfg(test)]
fn capture_begin() {
    x86_64::instructions::interrupts::without_interrupts(|| {
        *TX.lock() = Some(Vec::new());
    });
}

#[cfg(test)]
fn capture_take() -> Vec<Vec<u8>> {
    x86_64::instructions::interrupts::without_interrupts(|| TX.lock().take().unwrap_or_default())
}

fn emit(frame: &[u8]) -> Result<(), i32> {
    let captured = x86_64::instructions::interrupts::without_interrupts(|| {
        let mut tx = TX.lock();
        if let Some(q) = tx.as_mut() {
            q.push(frame.to_vec());
            true
        } else {
            false
        }
    });
    if captured {
        return Ok(());
    }
    if !crate::virtio_net::present() {
        return Err(ENETDOWN);
    }
    crate::virtio_net::send_frame(frame).map_err(|_| ENETDOWN)
}

fn wire_tx_possible() -> bool {
    our_ll() != UNSPEC && (crate::virtio_net::present() || capture_on())
}

/// NS, затем либо кадр захвата (без ожидания), либо до трёх раз по 300 мс.
/// Повторный вход из разбора кадра не ждёт: иначе разрешение соседа
/// зацикливается на собственном ответе.
fn nd_resolve(dst: &[u8; 16]) -> Result<[u8; 6], i32> {
    if let Some(mac) = nd_cached(dst) {
        return Ok(mac);
    }
    if !is_link_local(dst) {
        return Err(ENETUNREACH);
    }
    let (our_mac, our_ll) = identity().map_err(|_| ENETUNREACH)?;
    if ND_BUSY.swap(true, Ordering::SeqCst) {
        return Err(ENETUNREACH);
    }
    let _guard = NdGuard;
    let ns = build_ns(&our_mac, &our_ll, dst);
    if capture_on() || !crate::virtio_net::present() {
        emit(&ns)?;
        return Err(ENETUNREACH);
    }
    for _ in 0..3 {
        emit(&ns)?;
        let deadline = crate::time::monotonic_ns().saturating_add(300_000_000);
        let mut buf = [0u8; 1600];
        while crate::time::monotonic_ns() < deadline {
            let Some(n) = crate::virtio_net::recv_frame(&mut buf) else {
                core::hint::spin_loop();
                continue;
            };
            crate::net::ingest_frame(&buf[..n]);
            if let Some(mac) = nd_cached(dst) {
                return Ok(mac);
            }
        }
    }
    Err(ENETUNREACH)
}

fn zeros(n: usize) -> Vec<u8> {
    let mut v = Vec::new();
    v.resize(n, 0);
    v
}

fn build_ipv6(
    src_mac: &[u8; 6],
    dst_mac: &[u8; 6],
    src: &[u8; 16],
    dst: &[u8; 16],
    hop: u8,
    next: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut f = zeros(14 + 40 + payload.len());
    f[0..6].copy_from_slice(dst_mac);
    f[6..12].copy_from_slice(src_mac);
    put_be16(&mut f, 12, 0x86DD);
    f[14] = 0x60;
    put_be16(&mut f, 18, payload.len() as u16);
    f[20] = next;
    f[21] = hop;
    f[22..38].copy_from_slice(src);
    f[38..54].copy_from_slice(dst);
    f[54..].copy_from_slice(payload);
    f
}

fn build_ns(src_mac: &[u8; 6], src_ip: &[u8; 16], target: &[u8; 16]) -> Vec<u8> {
    let dst_ip = solicited_node(target);
    let dst_mac = multicast_mac(&dst_ip);
    let mut icmp = zeros(32);
    icmp[0] = 135;
    icmp[8..24].copy_from_slice(target);
    icmp[24] = 1;
    icmp[25] = 1;
    icmp[26..32].copy_from_slice(src_mac);
    let sum = upper_checksum(src_ip, &dst_ip, 58, &icmp);
    put_be16(&mut icmp, 2, sum);
    build_ipv6(src_mac, &dst_mac, src_ip, &dst_ip, HOP_NDP, 58, &icmp)
}

fn build_na(src_mac: &[u8; 6], our_ip: &[u8; 16], dst_mac: &[u8; 6], dst_ip: &[u8; 16]) -> Vec<u8> {
    let mut icmp = zeros(32);
    icmp[0] = 136;
    icmp[4] = 0x60;
    icmp[8..24].copy_from_slice(our_ip);
    icmp[24] = 2;
    icmp[25] = 1;
    icmp[26..32].copy_from_slice(src_mac);
    let sum = upper_checksum(our_ip, dst_ip, 58, &icmp);
    put_be16(&mut icmp, 2, sum);
    build_ipv6(src_mac, dst_mac, our_ip, dst_ip, HOP_NDP, 58, &icmp)
}

fn build_udp_frame(
    src_mac: &[u8; 6],
    dst_mac: &[u8; 6],
    src: &[u8; 16],
    dst: &[u8; 16],
    sport: u16,
    dport: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut seg = zeros(8 + payload.len());
    let udp_len = seg.len() as u16;
    put_be16(&mut seg, 0, sport);
    put_be16(&mut seg, 2, dport);
    put_be16(&mut seg, 4, udp_len);
    seg[8..].copy_from_slice(payload);
    let sum = upper_checksum(src, dst, 17, &seg);
    put_be16(&mut seg, 6, sum);
    build_ipv6(src_mac, dst_mac, src, dst, HOP_LIMIT, 17, &seg)
}

fn build_tcp_frame(
    src_mac: &[u8; 6],
    dst_mac: &[u8; 6],
    src: &[u8; 16],
    dst: &[u8; 16],
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut seg = zeros(20 + payload.len());
    put_be16(&mut seg, 0, sport);
    put_be16(&mut seg, 2, dport);
    put_be32(&mut seg, 4, seq);
    put_be32(&mut seg, 8, ack);
    seg[12] = 0x50;
    seg[13] = flags;
    put_be16(&mut seg, 14, TCP_RX.min(65535) as u16);
    seg[20..].copy_from_slice(payload);
    let sum = upper_checksum(src, dst, 6, &seg);
    put_be16(&mut seg, 16, sum);
    build_ipv6(src_mac, dst_mac, src, dst, HOP_LIMIT, 6, &seg)
}

fn icmp_opt(msg: &[u8], want: u8) -> Option<[u8; 6]> {
    let mut i = 24;
    while i + 1 < msg.len() {
        let kind = msg[i];
        let words = msg[i + 1] as usize;
        if words == 0 {
            return None;
        }
        let len = words * 8;
        if i + len > msg.len() {
            return None;
        }
        if kind == want && len >= 8 {
            let mut mac = [0u8; 6];
            mac.copy_from_slice(&msg[i + 2..i + 8]);
            return Some(mac);
        }
        i += len;
    }
    None
}

fn send_udp6(src: &[u8; 16], sport: u16, dst: &[u8; 16], dport: u16, payload: &[u8]) -> Result<(), i32> {
    if !is_link_local(dst) {
        return Err(ENETUNREACH);
    }
    let mac = nd_resolve(dst)?;
    let (our_mac, our_ip) = identity()?;
    if *src != our_ip {
        return Err(EINVAL);
    }
    let frame = build_udp_frame(&our_mac, &mac, src, dst, sport, dport, payload);
    emit(&frame)
}

fn send_tcp6(
    src: &[u8; 16],
    sport: u16,
    dst: &[u8; 16],
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Result<(), i32> {
    if !is_link_local(dst) {
        return Err(ENETUNREACH);
    }
    let mac = nd_resolve(dst)?;
    let (our_mac, our_ip) = identity()?;
    if *src != our_ip {
        return Err(EINVAL);
    }
    let frame = build_tcp_frame(&our_mac, &mac, src, dst, sport, dport, seq, ack, flags, payload);
    emit(&frame)
}

/// Разобрать кадр Ethernet с ethertype `0x86DD`. Чужой адрес и битая сумма
/// отбрасываются. Петля сюда не приходит: `::1` кадром не бывает.
pub fn ingest(frame: &[u8]) {
    if frame.len() < 54 {
        return;
    }
    if be16(frame, 12) != 0x86DD || frame[14] >> 4 != 6 {
        return;
    }
    let pay_len = be16(frame, 18) as usize;
    let next = frame[20];
    let hop = frame[21];
    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src.copy_from_slice(&frame[22..38]);
    dst.copy_from_slice(&frame[38..54]);
    if frame.len() < 54 + pay_len {
        return;
    }
    let payload = &frame[54..54 + pay_len];
    let mut smac = [0u8; 6];
    smac.copy_from_slice(&frame[6..12]);
    match next {
        58 => ingest_icmp(hop, &src, &dst, smac, payload),
        17 => ingest_udp(&src, &dst, payload),
        6 => ingest_tcp(&src, &dst, payload),
        _ => {}
    }
}

fn for_us(dst: &[u8; 16]) -> bool {
    let ll = our_ll();
    ll != UNSPEC && *dst == ll
}

fn ingest_icmp(hop: u8, src: &[u8; 16], dst: &[u8; 16], smac: [u8; 6], msg: &[u8]) {
    if hop != HOP_NDP || msg.len() < 24 || msg[1] != 0 {
        return;
    }
    if !upper_sum_ok(src, dst, 58, msg) {
        return;
    }
    let mut target = [0u8; 16];
    target.copy_from_slice(&msg[8..24]);
    match msg[0] {
        135 => {
            // DAD (источник `::`) не защищаем и не отвечаем.
            if is_unspec(src) {
                return;
            }
            let ll = our_ll();
            if ll == UNSPEC || target != ll {
                return;
            }
            let sol = solicited_node(&ll);
            if *dst != ll && *dst != sol {
                return;
            }
            if let Some(mac) = icmp_opt(msg, 1) {
                nd_learn(*src, mac);
            }
            let (our_mac, our_ip) = match identity() {
                Ok(v) => v,
                Err(_) => return,
            };
            if smac == [0; 6] {
                return;
            }
            let na = build_na(&our_mac, &our_ip, &smac, src);
            let _ = emit(&na);
        }
        136 => {
            if !is_link_local(&target) {
                return;
            }
            if let Some(mac) = icmp_opt(msg, 2) {
                nd_learn(target, mac);
            }
        }
        _ => {}
    }
}

fn ingest_udp(src: &[u8; 16], dst: &[u8; 16], payload: &[u8]) {
    if !for_us(dst) || !is_link_local(src) || payload.len() < 8 {
        return;
    }
    let ulen = be16(payload, 4) as usize;
    if ulen < 8 || ulen > payload.len() {
        return;
    }
    let segment = &payload[..ulen];
    if !upper_sum_ok(src, dst, 17, segment) {
        return;
    }
    let sport = be16(segment, 0);
    let dport = be16(segment, 2);
    deliver(*dst, dport, *src, sport, &segment[8..]);
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
    crate::net::pump();
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
    let local = if is_loopback(&addr) {
        LOOPBACK
    } else {
        let ll = our_ll();
        if ll == UNSPEC {
            return Err(ENETDOWN);
        }
        ll
    };
    with_udp(|tab| {
        if tab.get(id).and_then(|s| s.as_ref()).is_none() {
            return Err(EFAULT);
        }
        if tab[id].as_ref().unwrap().bound {
            let bound = tab[id].as_ref().unwrap().addr;
            if is_loopback(&bound) && !is_loopback(&addr) {
                return Err(EINVAL);
            }
            if is_link_local(&bound) && is_loopback(&addr) {
                return Err(EINVAL);
            }
        } else {
            let port = alloc_port(tab);
            if port == 0 {
                return Err(EADDRINUSE);
            }
            let s = tab[id].as_mut().unwrap();
            s.port = port;
            s.addr = local;
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
    let (src_bound, sport, dest, fresh) = with_udp(|tab| -> Result<_, i32> {
        if tab.get(id).and_then(|s| s.as_ref()).is_none() {
            return Err(EFAULT);
        }
        let dest = dst.or_else(|| tab[id].as_ref().unwrap().peer).ok_or(EDESTADDRREQ)?;
        check_dest(&dest.0, dest.1)?;
        let fresh = !tab[id].as_ref().unwrap().bound;
        if fresh {
            let port = alloc_port(tab);
            if port == 0 {
                return Err(EADDRINUSE);
            }
            let s = tab[id].as_mut().unwrap();
            s.port = port;
            // Link-local дописывается снаружи: здесь нельзя брать lock канала.
            s.addr = if is_loopback(&dest.0) { LOOPBACK } else { UNSPEC };
            s.bound = true;
        }
        let s = tab[id].as_ref().unwrap();
        Ok((s.addr, s.port, dest, fresh))
    })?;
    if is_loopback(&dest.0) {
        if is_link_local(&src_bound) {
            return Err(EINVAL);
        }
        let src = if is_unspec(&src_bound) { LOOPBACK } else { src_bound };
        if !is_loopback(&src) {
            return Err(EINVAL);
        }
        deliver(dest.0, dest.1, src, sport, data);
        return Ok(data.len());
    }
    if is_loopback(&src_bound) {
        return Err(EINVAL);
    }
    if data.len() > WIRE_DGRAM_MAX {
        return Err(EMSGSIZE);
    }
    let src = if is_unspec(&src_bound) {
        let ll = our_ll();
        if ll == UNSPEC {
            return Err(ENETDOWN);
        }
        if fresh {
            with_udp(|tab| {
                if let Some(s) = tab.get_mut(id).and_then(|s| s.as_mut()) {
                    if is_unspec(&s.addr) {
                        s.addr = ll;
                    }
                }
            });
        }
        ll
    } else {
        src_bound
    };
    // Себе — в память, без кадра и без NDP. Чужому link-local — только сосед.
    if dest.0 == src {
        deliver(dest.0, dest.1, src, sport, data);
        return Ok(data.len());
    }
    send_udp6(&src, sport, &dest.0, dest.1, data)?;
    Ok(data.len())
}

pub fn udp_recv(id: usize, buf: &mut [u8]) -> Result<(usize, [u8; 16], u16), i32> {
    crate::net::pump();
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
    /// Провод link-local: seq/ack, повтор, окно. Петля держит это выключенным.
    wire: bool,
    estab: bool,
    seq: u32,
    rnext: u32,
    unacked: Vec<(u32, Vec<u8>, u64)>,
    win: u32,
    reorder: Vec<(u32, Vec<u8>)>,
    reorder_fin: bool,
    rtx: u8,
    cwnd: u32,
    ssthresh: u32,
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
        wire: false,
        estab: false,
        seq: 0,
        rnext: 0,
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
    let fins = with_tcp(|tab| {
        let mut fins = Vec::new();
        tcp_drop(tab, id, &mut fins);
        fins
    });
    // FIN после лока: отправка берёт NDP и не должна ждать таблицу TCP.
    for fin in fins {
        let _ = send_tcp6(
            &fin.src,
            fin.sport,
            &fin.dst,
            fin.dport,
            fin.seq,
            fin.ack,
            TH_ACK | TH_FIN,
            &[],
        );
    }
}

fn tcp_drop(tab: &mut [Option<TcpSock>; TCP_N], id: usize, fins: &mut Vec<WireOut>) {
    let Some(Some(s)) = tab.get_mut(id) else {
        return;
    };
    s.refs = s.refs.saturating_sub(1);
    if s.refs > 0 {
        return;
    }
    let sock = tab[id].take().unwrap();
    if sock.wire && sock.estab && !sock.eof && !sock.listen {
        fins.push(WireOut {
            src: sock.addr,
            sport: sock.port,
            dst: sock.peer_addr,
            dport: sock.peer_port,
            seq: sock.seq,
            ack: sock.rnext,
            data: Vec::new(),
        });
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
        tcp_drop(tab, child, fins);
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
    crate::net::pump();
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
            if s.peer.is_some() || s.wire || s.eof {
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
        if tab[id].as_ref().unwrap().listen
            || tab[id].as_ref().unwrap().peer.is_some()
            || tab[id].as_ref().unwrap().wire
        {
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
            (cur.bound, cur.port, cur.peer.is_some() || cur.wire)
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
    if !is_loopback(&dst) {
        return tcp_connect_wire(id, dst, dst_port);
    }
    with_tcp(|tab| {
        let (listening, connected) = {
            let Some(client) = tab.get(id).and_then(|s| s.as_ref()) else {
                return Err(EFAULT);
            };
            (client.listen, client.peer.is_some() || client.wire)
        };
        if listening {
            return Err(EINVAL);
        }
        if connected {
            return Err(EISCONN);
        }
        if tab[id].as_ref().unwrap().bound && is_link_local(&tab[id].as_ref().unwrap().addr) {
            return Err(EINVAL);
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
        let mut born = tcp_fresh(false);
        born.bound = true;
        born.addr = local;
        born.port = dst_port;
        born.peer_addr = LOOPBACK;
        born.peer_port = cport;
        born.peer = Some(id);
        born.parent = Some(lid);
        tab[child] = Some(born);
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

struct WireOut {
    src: [u8; 16],
    sport: u16,
    dst: [u8; 16],
    dport: u16,
    seq: u32,
    ack: u32,
    data: Vec<u8>,
}

pub fn tcp_send(id: usize, data: &[u8]) -> Result<usize, i32> {
    if data.is_empty() {
        return Ok(0);
    }
    let reserved = with_tcp(|tab| -> Result<Option<WireOut>, i32> {
        let Some(s) = tab.get(id).and_then(|s| s.as_ref()) else {
            return Err(EFAULT);
        };
        if s.listen {
            return Err(ENOTCONN);
        }
        if !s.wire {
            return Ok(None);
        }
        if s.eof {
            return Err(EPIPE);
        }
        if !s.estab {
            return Err(ENOTCONN);
        }
        let now = crate::time::monotonic_ns();
        let s = tab[id].as_mut().unwrap();
        let inflight: u32 = s.unacked.iter().map(|(_, d, _)| d.len() as u32).sum();
        if s.win == 0 {
            return Err(EAGAIN);
        }
        let budget = s.win.min(s.cwnd);
        let avail = budget.saturating_sub(inflight) as usize;
        let n = data.len().min(MSS as usize).min(avail);
        if n == 0 {
            return Err(EAGAIN);
        }
        let seq = s.seq;
        s.seq = s.seq.wrapping_add(n as u32);
        s.unacked.push((seq, data[..n].to_vec(), now));
        Ok(Some(WireOut {
            src: s.addr,
            sport: s.port,
            dst: s.peer_addr,
            dport: s.peer_port,
            seq,
            ack: s.rnext,
            data: data[..n].to_vec(),
        }))
    })?;
    let Some(seg) = reserved else {
        return with_tcp(|tab| {
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
        });
    };
    match send_tcp6(
        &seg.src,
        seg.sport,
        &seg.dst,
        seg.dport,
        seg.seq,
        seg.ack,
        TH_ACK | TH_PSH,
        &seg.data,
    ) {
        Ok(()) => Ok(seg.data.len()),
        Err(e) => {
            with_tcp(|tab| {
                if let Some(s) = tab.get_mut(id).and_then(|s| s.as_mut()) {
                    if s.unacked.last().map(|(sq, _, _)| *sq) == Some(seg.seq) {
                        s.unacked.pop();
                        s.seq = seg.seq;
                    }
                }
            });
            Err(e)
        }
    }
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
            let waiting = s.peer.is_some() || (s.wire && s.estab);
            return Err(if waiting { EAGAIN } else { ENOTCONN });
        }
        let n = s.rx.len().min(buf.len());
        buf[..n].copy_from_slice(&s.rx[..n]);
        s.rx.drain(..n);
        Ok((n, s.peer_addr, s.peer_port))
    })
}

fn tcp_isn(id: usize) -> u32 {
    (crate::time::monotonic_ns() as u32)
        .wrapping_mul(0x9E37_79B1)
        .wrapping_add((id as u32).wrapping_mul(0x85EB_CA6B))
        | 1
}

fn clear_wire(id: usize) {
    with_tcp(|tab| {
        if let Some(s) = tab.get_mut(id).and_then(|s| s.as_mut()) {
            s.wire = false;
            s.estab = false;
            s.seq = 0;
            s.rnext = 0;
            s.peer_addr = UNSPEC;
            s.peer_port = 0;
            s.unacked.clear();
        }
    });
}

/// Link-local SYN. Без карты и без захвата сокет не меняется.
/// Неблокирующий возвращает `EINPROGRESS`, блокирующий ждёт SYN-ACK.
fn tcp_connect_wire(id: usize, dst: [u8; 16], dst_port: u16) -> Result<(), i32> {
    if !is_link_local(&dst) || !wire_tx_possible() {
        return Err(ENETUNREACH);
    }
    let our = our_ll();
    if our == UNSPEC {
        return Err(ENETUNREACH);
    }
    enum Phase {
        Continue { isn: u32, nonblock: bool },
        Fresh { nonblock: bool },
    }
    let phase = with_tcp(|tab| -> Result<Phase, i32> {
        let Some(s) = tab.get(id).and_then(|s| s.as_ref()) else {
            return Err(EFAULT);
        };
        if s.listen {
            return Err(EINVAL);
        }
        if s.estab || s.peer.is_some() {
            return Err(EISCONN);
        }
        if s.bound && is_loopback(&s.addr) {
            return Err(EINVAL);
        }
        if s.wire && s.seq != 0 {
            return Ok(Phase::Continue {
                isn: s.seq,
                nonblock: s.nonblock,
            });
        }
        Ok(Phase::Fresh { nonblock: s.nonblock })
    })?;
    // Сосед до правки сокета: промах NDP оставляет его чистым.
    let continued = matches!(phase, Phase::Continue { .. });
    if !continued {
        nd_resolve(&dst)?;
    }
    let (isn, nonblock) = match phase {
        Phase::Continue { isn, nonblock } => (isn, nonblock),
        Phase::Fresh { nonblock } => {
            let isn = with_tcp(|tab| -> Result<u32, i32> {
                let (need_port, existing) = {
                    let Some(s) = tab.get(id).and_then(|s| s.as_ref()) else {
                        return Err(EFAULT);
                    };
                    if s.estab || s.peer.is_some() {
                        return Err(EISCONN);
                    }
                    (!(s.bound && s.port != 0), s.port)
                };
                let port = if need_port {
                    let p = tcp_alloc_port(tab);
                    if p == 0 {
                        return Err(EADDRINUSE);
                    }
                    p
                } else {
                    existing
                };
                let isn = tcp_isn(id);
                let s = tab[id].as_mut().unwrap();
                if need_port {
                    s.port = port;
                    s.bound = true;
                }
                if is_unspec(&s.addr) {
                    s.addr = our;
                }
                s.wire = true;
                s.estab = false;
                s.seq = isn;
                s.peer_addr = dst;
                s.peer_port = dst_port;
                s.eof = false;
                s.cwnd = MSS;
                s.ssthresh = CWND_MAX;
                Ok(isn)
            })?;
            (isn, nonblock)
        }
    };
    let sport = with_tcp(|tab| {
        tab.get(id)
            .and_then(|s| s.as_ref())
            .map(|s| s.port)
            .unwrap_or(0)
    });
    if sport == 0 {
        clear_wire(id);
        return Err(EFAULT);
    }
    if let Err(e) = send_tcp6(&our, sport, &dst, dst_port, isn, 0, TH_SYN, &[]) {
        if !continued {
            clear_wire(id);
        }
        return Err(e);
    }
    if nonblock {
        let estab = with_tcp(|tab| {
            tab.get(id)
                .and_then(|s| s.as_ref())
                .map(|s| s.estab)
                .unwrap_or(false)
        });
        return if estab { Ok(()) } else { Err(EINPROGRESS) };
    }
    for _ in 0..3 {
        let deadline = crate::time::monotonic_ns().saturating_add(2_500_000_000);
        while crate::time::monotonic_ns() < deadline {
            crate::net::pump();
            let (estab, dead) = with_tcp(|tab| {
                tab.get(id)
                    .and_then(|s| s.as_ref())
                    .map(|s| (s.estab, s.eof && !s.estab))
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
        let _ = send_tcp6(&our, sport, &dst, dst_port, isn, 0, TH_SYN, &[]);
    }
    Err(ETIMEDOUT)
}

struct Seg {
    src: [u8; 16],
    sport: u16,
    dst: [u8; 16],
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
}

fn send_seg(seg: &Seg) {
    let _ = send_tcp6(
        &seg.src,
        seg.sport,
        &seg.dst,
        seg.dport,
        seg.seq,
        seg.ack,
        seg.flags,
        &[],
    );
}

fn tcp_rst(remote: &[u8; 16], remote_port: u16, local_port: u16, rx_seq: u32) {
    let src = our_ll();
    if src == UNSPEC {
        return;
    }
    let _ = send_tcp6(
        &src,
        local_port,
        remote,
        remote_port,
        0,
        rx_seq.wrapping_add(1),
        TH_RST | TH_ACK,
        &[],
    );
}

fn ingest_tcp(src: &[u8; 16], dst: &[u8; 16], segment: &[u8]) {
    if !for_us(dst) || !is_link_local(src) || segment.len() < 20 {
        return;
    }
    let data_off = ((segment[12] >> 4) as usize) * 4;
    if data_off < 20 || segment.len() < data_off {
        return;
    }
    if !upper_sum_ok(src, dst, 6, segment) {
        return;
    }
    let sport = be16(segment, 0);
    let dport = be16(segment, 2);
    let rx_seq = be32(segment, 4);
    let rx_ack = be32(segment, 8);
    let flags = segment[13];
    let window = u32::from(be16(segment, 14));
    let payload = &segment[data_off..];

    if flags & TH_SYN != 0 && flags & TH_ACK == 0 {
        let reply = with_tcp(|tab| -> Result<Seg, ()> {
            let lid = tab.iter().position(|s| {
                s.as_ref()
                    .map(|s| s.listen && s.port == dport && (is_unspec(&s.addr) || s.addr == *dst))
                    .unwrap_or(false)
            });
            let Some(lid) = lid else {
                return Err(());
            };
            let (limit, queued) = {
                let ls = tab[lid].as_ref().unwrap();
                (ls.backlog_max, ls.backlog.len())
            };
            let free = tab.iter().position(|s| s.is_none());
            let (Some(child), true) = (free, queued < limit) else {
                return Err(());
            };
            let isn = tcp_isn(child);
            let mut born = tcp_fresh(false);
            born.bound = true;
            born.wire = true;
            born.seq = isn;
            born.rnext = rx_seq.wrapping_add(1);
            born.addr = *dst;
            born.port = dport;
            born.peer_addr = *src;
            born.peer_port = sport;
            born.parent = Some(lid);
            born.cwnd = MSS;
            born.ssthresh = CWND_MAX;
            tab[child] = Some(born);
            tab[lid].as_mut().unwrap().backlog.push(child);
            Ok(Seg {
                src: *dst,
                sport: dport,
                dst: *src,
                dport: sport,
                seq: isn,
                ack: rx_seq.wrapping_add(1),
                flags: TH_SYN | TH_ACK,
            })
        });
        match reply {
            Ok(seg) => send_seg(&seg),
            Err(()) => tcp_rst(src, sport, dport, rx_seq),
        }
        return;
    }

    enum Act {
        None,
        Rst,
        Reply(Seg),
    }
    let act = with_tcp(|tab| -> Act {
        let sid = tab.iter().position(|s| {
            s.as_ref()
                .map(|s| s.wire && s.port == dport && s.peer_addr == *src && s.peer_port == sport)
                .unwrap_or(false)
        });
        let Some(sid) = sid else {
            return if flags & TH_RST == 0 { Act::Rst } else { Act::None };
        };
        let mut reply = false;
        {
            let s = tab[sid].as_mut().unwrap();
            if flags & TH_RST != 0 {
                s.eof = true;
                s.estab = false;
                s.unacked.clear();
            } else if flags & TH_SYN != 0 && flags & TH_ACK != 0 && !s.estab {
                if rx_ack == s.seq.wrapping_add(1) {
                    s.estab = true;
                    s.seq = s.seq.wrapping_add(1);
                    s.rnext = rx_seq.wrapping_add(1);
                    s.win = window;
                    reply = true;
                }
            } else if flags & TH_ACK != 0 && !s.estab {
                if rx_ack == s.seq.wrapping_add(1) {
                    s.estab = true;
                    s.seq = s.seq.wrapping_add(1);
                    s.win = window;
                }
            } else if s.estab {
                if flags & TH_ACK != 0 {
                    s.win = window;
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
                    let before = s.rnext;
                    if !payload.is_empty() {
                        let space = TCP_RX.saturating_sub(s.rx.len());
                        let n = space.min(payload.len());
                        s.rx.extend_from_slice(&payload[..n]);
                        s.rnext = s.rnext.wrapping_add(n as u32);
                    }
                    loop {
                        let hit = s.reorder.iter().position(|(sq, _)| *sq == s.rnext);
                        let Some(i) = hit else { break };
                        let (_, data) = s.reorder.remove(i);
                        let space = TCP_RX.saturating_sub(s.rx.len());
                        let n = space.min(data.len());
                        s.rx.extend_from_slice(&data[..n]);
                        s.rnext = s.rnext.wrapping_add(n as u32);
                    }
                    if s.reorder.is_empty() && s.reorder_fin {
                        s.reorder_fin = false;
                        s.eof = true;
                        s.rnext = s.rnext.wrapping_add(1);
                    }
                    if flags & TH_FIN != 0 {
                        s.eof = true;
                        s.rnext = s.rnext.wrapping_add(1);
                    }
                    // Пустой ACK по месту не отражаем: иначе два стека гоняют его вечно.
                    reply = s.rnext != before;
                } else {
                    let ahead = rx_seq.wrapping_sub(s.rnext);
                    if flags & (TH_PSH | TH_FIN) != 0 && ahead > 0 {
                        let held: usize = s.reorder.iter().map(|(_, d)| d.len()).sum();
                        if held + payload.len() <= TCP_RX {
                            s.reorder.push((rx_seq, payload.to_vec()));
                        }
                        if flags & TH_FIN != 0 {
                            s.reorder_fin = true;
                        }
                    }
                    reply = true;
                }
            }
        }
        if reply {
            let s = tab[sid].as_ref().unwrap();
            Act::Reply(Seg {
                src: *dst,
                sport: s.port,
                dst: s.peer_addr,
                dport: s.peer_port,
                seq: s.seq,
                ack: s.rnext,
                flags: TH_ACK,
            })
        } else {
            Act::None
        }
    });
    match act {
        Act::Reply(seg) => send_seg(&seg),
        Act::Rst => tcp_rst(src, sport, dport, rx_seq),
        Act::None => {}
    }
}

/// Повтор неподтверждённого. Восемь тихих RTO рвут сокет.
pub fn retransmit() {
    #[cfg(test)]
    if !rtx_enter() {
        return;
    }
    retransmit_segments();
    #[cfg(test)]
    {
        RTX_DEPTH.fetch_sub(1, Ordering::SeqCst);
    }
}

#[cfg(test)]
fn rtx_enter() -> bool {
    if RTX_HOLD.load(Ordering::SeqCst) {
        return false;
    }
    RTX_DEPTH.fetch_add(1, Ordering::SeqCst);
    if RTX_HOLD.load(Ordering::SeqCst) {
        RTX_DEPTH.fetch_sub(1, Ordering::SeqCst);
        return false;
    }
    true
}

#[cfg(test)]
fn rtx_hold(on: bool) {
    RTX_HOLD.store(on, Ordering::SeqCst);
}

/// Ждать, пока вход, уже прошедший проверку, допишет кадр. Новые тики держатся.
#[cfg(test)]
fn rtx_wait_idle() {
    let start = crate::time::monotonic_ns();
    while RTX_DEPTH.load(Ordering::SeqCst) != 0 {
        if crate::time::monotonic_ns().saturating_sub(start) > 50_000_000 {
            return;
        }
        core::hint::spin_loop();
    }
}

/// Повтор этого CPU. Удержание тика не действует.
#[cfg(test)]
fn retransmit_forced() {
    RTX_FORCE.store(true, Ordering::SeqCst);
    retransmit_segments();
    RTX_FORCE.store(false, Ordering::SeqCst);
}

fn retransmit_segments() {
    let now = crate::time::monotonic_ns();
    let mut jobs: Vec<WireOut> = Vec::new();
    with_tcp(|tab| {
        for s in tab.iter_mut().flatten() {
            #[cfg(test)]
            if RTX_HOLD.load(Ordering::SeqCst) && !RTX_FORCE.load(Ordering::SeqCst) {
                continue;
            }
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
            s.ssthresh = (inflight / 2).max(MSS * 2);
            s.cwnd = MSS;
            if s.rtx >= RTO_TC {
                s.eof = true;
                s.estab = false;
                s.unacked.clear();
                continue;
            }
            jobs.push(WireOut {
                src: s.addr,
                sport: s.port,
                dst: s.peer_addr,
                dport: s.peer_port,
                seq,
                ack: s.rnext,
                data,
            });
        }
    });
    for seg in jobs {
        let _ = send_tcp6(
            &seg.src,
            seg.sport,
            &seg.dst,
            seg.dport,
            seg.seq,
            seg.ack,
            TH_ACK | TH_PSH,
            &seg.data,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::{TH_ACK, TH_FIN, TH_PSH, TH_RST, TH_SYN};
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

    fn ll_byte(b: u8) -> [u8; 16] {
        let mut a = [0u8; 16];
        a[0] = 0xfe;
        a[1] = 0x80;
        a[15] = b;
        a
    }

    fn sum_ok(frame: &[u8], proto: u8) -> bool {
        if frame.len() < 54 || u16::from_be_bytes([frame[12], frame[13]]) != 0x86DD {
            return false;
        }
        let plen = u16::from_be_bytes([frame[18], frame[19]]) as usize;
        if frame.len() < 54 + plen || frame[20] != proto {
            return false;
        }
        let mut src = [0u8; 16];
        let mut dst = [0u8; 16];
        src.copy_from_slice(&frame[22..38]);
        dst.copy_from_slice(&frame[38..54]);
        upper_sum_ok(&src, &dst, proto, &frame[54..54 + plen])
    }

    #[test_case]
    fn ipv6_link_local_ndp_udp_and_tcp() {
        serial_print!("test ipv6_link_local_ndp_udp_and_tcp... ");
        let mac = [0x52u8, 0x54, 0x00, 0x12, 0x34, 0x56];
        let our = super::eui64(&mac);
        assert_eq!(
            our,
            [
                0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x50, 0x54, 0x00, 0xff, 0xfe, 0x12, 0x34, 0x56
            ]
        );
        let sol = super::solicited_node(&our);
        assert_eq!(sol[0], 0xff);
        assert_eq!(sol[1], 0x02);
        assert_eq!(sol[11], 0x01);
        assert_eq!(sol[12], 0xff);
        assert_eq!(super::multicast_mac(&sol), [0x33, 0x33, 0xff, 0x12, 0x34, 0x56]);
        assert!(super::is_link_local(&our));
        assert!(!super::is_link_local(&LOOPBACK));
        let mut site = [0u8; 16];
        site[0] = 0xfe;
        site[1] = 0xc0;
        site[15] = 1;
        assert!(!super::is_link_local(&site));
        let mut wide = [0u8; 16];
        wide[0] = 0xfe;
        wide[1] = 0xbf;
        wide[15] = 1;
        assert!(super::is_link_local(&wide));

        let real = super::with_link(|link| if link.up { Some(link.mac) } else { None });
        super::attach(mac);
        assert_eq!(super::our_ll(), our);

        let peer = ll_byte(2);
        let peer_mac = [0x02u8, 0x11, 0x22, 0x33, 0x44, 0x55];
        let mut far = [0u8; 16];
        far[0] = 0x20;
        far[1] = 0x01;
        far[15] = 1;

        super::capture_begin();
        let u = udp_open(true).expect("udp");
        assert_eq!(udp_send(u, b"x", Some((far, 9))).expect_err("global"), ENETUNREACH);
        assert_eq!(udp_send(u, b"x", Some((site, 9))).expect_err("site"), ENETUNREACH);
        assert!(super::capture_take().is_empty(), "global must not emit");

        super::capture_begin();
        assert_eq!(udp_send(u, b"x", Some((wide, 9))).expect_err("wide"), ENETUNREACH);
        let ns_frames = super::capture_take();
        assert_eq!(ns_frames.len(), 1, "unresolved link-local is one NS");
        let ns = &ns_frames[0];
        assert_eq!(&ns[0..6], &super::multicast_mac(&super::solicited_node(&wide)));
        assert_eq!(ns[21], 255, "ndp hop limit");
        assert_eq!(ns[54], 135, "NS");
        assert!(sum_ok(ns, 58), "NS checksum");
        assert_eq!(&ns[62..78], &wide);

        // Битый hop limit не отвечает NA.
        super::capture_begin();
        let mut bad_hop = super::build_ns(&peer_mac, &peer, &our);
        bad_hop[21] = 64;
        super::ingest(&bad_hop);
        assert!(super::capture_take().is_empty(), "hop 64 is dropped");

        super::capture_begin();
        let ask = super::build_ns(&peer_mac, &peer, &our);
        super::ingest(&ask);
        let na_frames = super::capture_take();
        assert_eq!(na_frames.len(), 1, "NS gets one NA");
        let na = &na_frames[0];
        assert_eq!(&na[0..6], &peer_mac);
        assert_eq!(&na[6..12], &mac);
        assert_eq!(na[21], 255);
        assert_eq!(na[54], 136);
        assert_eq!(na[58], 0x60, "solicited override");
        assert_eq!(&na[62..78], &our);
        assert_eq!(na[78], 2, "TLLA");
        assert_eq!(&na[80..86], &mac);
        assert!(sum_ok(na, 58));
        assert_eq!(super::nd_cached(&peer), Some(peer_mac));

        udp_bind(u, our, 19110).expect("bind ll");
        let mut other = our;
        other[15] ^= 0xff;
        assert_eq!(udp_bind(u, other, 19111).expect_err("foreign ll"), EADDRNOTAVAIL);
        super::capture_begin();
        let n = udp_send(u, b"hi", Some((peer, 19112))).expect("udp wire");
        assert_eq!(n, 2);
        let udp_frames = super::capture_take();
        assert_eq!(udp_frames.len(), 1);
        let uf = &udp_frames[0];
        assert_eq!(&uf[0..6], &peer_mac);
        assert_eq!(uf[21], 64);
        assert!(sum_ok(uf, 17));
        assert_eq!(&uf[54 + 8..], b"hi");

        let got = super::build_udp_frame(&peer_mac, &mac, &peer, &our, 19112, 19110, b"pong");
        super::ingest(&got);
        let mut ubuf = [0u8; 8];
        let (n, src, sport) = udp_recv(u, &mut ubuf).expect("udp recv");
        assert_eq!(&ubuf[..n], b"pong");
        assert_eq!(src, peer);
        assert_eq!(sport, 19112);
        let mut bad = got.clone();
        let last = bad.len() - 1;
        bad[last] ^= 0xff;
        super::ingest(&bad);
        assert_eq!(udp_recv(u, &mut ubuf).expect_err("bad sum"), EAGAIN);

        super::capture_begin();
        assert_eq!(udp_send(u, b"loop", Some((LOOPBACK, 19110))).expect_err("from ll"), EINVAL);
        let self_n = udp_send(u, b"me", Some((our, 19110))).expect("self");
        assert_eq!(self_n, 2);
        let (n, _, _) = udp_recv(u, &mut ubuf).expect("self recv");
        assert_eq!(&ubuf[..n], b"me");
        assert!(super::capture_take().is_empty(), "loopback and self build no frame");
        let big = super::zeros(1453);
        assert_eq!(udp_send(u, &big, Some((peer, 9))).expect_err("mtu"), EMSGSIZE);
        udp_close(u);

        // Слушатель на ::1 проводной SYN не берёт.
        let loop_lst = tcp_open(true).expect("loop lst");
        tcp_bind(loop_lst, LOOPBACK, 19140).expect("loop bind");
        tcp_listen(loop_lst, 1).expect("loop listen");
        super::capture_begin();
        let stray = super::build_tcp_frame(&peer_mac, &mac, &peer, &our, 41000, 19140, 7, 0, TH_SYN, &[]);
        super::ingest(&stray);
        let rst = super::capture_take();
        assert_eq!(rst.len(), 1);
        assert_eq!(rst[0][67] & TH_RST, TH_RST);
        assert!(sum_ok(&rst[0], 6));
        assert_eq!(tcp_accept(loop_lst).expect_err("no child"), EAGAIN);
        tcp_close(loop_lst);

        let lst = tcp_open(true).expect("lst");
        tcp_bind(lst, our, 19120).expect("tbind");
        tcp_listen(lst, 2).expect("tlisten");
        super::capture_begin();
        let syn = super::build_tcp_frame(&peer_mac, &mac, &peer, &our, 41001, 19120, 1000, 0, TH_SYN, &[]);
        super::ingest(&syn);
        let synack = super::capture_take();
        assert_eq!(synack.len(), 1);
        assert_eq!(synack[0][67], TH_SYN | TH_ACK);
        assert!(sum_ok(&synack[0], 6));
        let isn = u32::from_be_bytes([synack[0][58], synack[0][59], synack[0][60], synack[0][61]]);
        assert_eq!(u32::from_be_bytes([synack[0][62], synack[0][63], synack[0][64], synack[0][65]]), 1001);
        let ack = super::build_tcp_frame(
            &peer_mac,
            &mac,
            &peer,
            &our,
            41001,
            19120,
            1001,
            isn.wrapping_add(1),
            TH_ACK,
            &[],
        );
        super::ingest(&ack);
        let (acc, acc_peer, acc_port) = tcp_accept(lst).expect("accept");
        assert_eq!(acc_peer, peer);
        assert_eq!(acc_port, 41001);
        let ahead = super::build_tcp_frame(
            &peer_mac,
            &mac,
            &peer,
            &our,
            41001,
            19120,
            1005,
            isn.wrapping_add(1),
            TH_ACK | TH_PSH,
            b"BBBB",
        );
        let hole = super::build_tcp_frame(
            &peer_mac,
            &mac,
            &peer,
            &our,
            41001,
            19120,
            1001,
            isn.wrapping_add(1),
            TH_ACK | TH_PSH,
            b"AAAA",
        );
        super::capture_begin();
        super::ingest(&ahead);
        super::ingest(&hole);
        let _acks = super::capture_take();
        let mut tbuf = [0u8; 8];
        let (n, _, _) = tcp_recv(acc, &mut tbuf).expect("reorder");
        assert_eq!(&tbuf[..n], b"AAAABBBB");
        let fin = super::build_tcp_frame(
            &peer_mac,
            &mac,
            &peer,
            &our,
            41001,
            19120,
            1009,
            isn.wrapping_add(1),
            TH_ACK | TH_FIN,
            &[],
        );
        super::ingest(&fin);
        let (n, _, _) = tcp_recv(acc, &mut tbuf).expect("fin");
        assert_eq!(n, 0);
        tcp_close(acc);
        tcp_close(lst);

        let cli = tcp_open(true).expect("cli");
        super::capture_begin();
        assert_eq!(tcp_connect(cli, peer, 19130).expect_err("syn"), EINPROGRESS);
        let syns = super::capture_take();
        assert_eq!(syns.len(), 1);
        assert_eq!(syns[0][67], TH_SYN);
        assert!(sum_ok(&syns[0], 6));
        assert_eq!(&syns[0][0..6], &peer_mac);
        let cseq = u32::from_be_bytes([syns[0][58], syns[0][59], syns[0][60], syns[0][61]]);
        let cport = u16::from_be_bytes([syns[0][54], syns[0][55]]);
        let synack_in = super::build_tcp_frame(
            &peer_mac,
            &mac,
            &peer,
            &our,
            19130,
            cport,
            5000,
            cseq.wrapping_add(1),
            TH_SYN | TH_ACK,
            &[],
        );
        super::capture_begin();
        super::ingest(&synack_in);
        let hshake = super::capture_take();
        assert_eq!(hshake.len(), 1, "third ack");
        assert_eq!(hshake[0][67], TH_ACK);
        assert!(sum_ok(&hshake[0], 6));
        super::capture_begin();
        assert_eq!(tcp_send(cli, b"xy").expect("cdata"), 2);
        let data = super::capture_take();
        assert_eq!(data.len(), 1);
        assert_eq!(&data[0][74..], b"xy");
        assert_eq!(data[0][67] & TH_PSH, TH_PSH);
        assert!(sum_ok(&data[0], 6));
        // Тик другого CPU забирает повтор между возвратом retransmit и
        // capture_take: штамп уже обновлён, кадр уходит в карту после взятия.
        // Удержание отсекает новый тик и уже вошедший разбор. Сосед снова в
        // кэше, иначе отправка повторного сегмента молча кончается отказом.
        super::rtx_hold(true);
        super::rtx_wait_idle();
        assert_eq!(super::RTX_DEPTH.load(super::Ordering::SeqCst), 0, "rto idle");
        super::nd_learn(peer, peer_mac);
        let busy_at = crate::time::monotonic_ns();
        while super::ND_BUSY.load(super::Ordering::SeqCst) {
            if crate::time::monotonic_ns().saturating_sub(busy_at) > 50_000_000 {
                break;
            }
            core::hint::spin_loop();
        }
        assert!(!super::ND_BUSY.load(super::Ordering::SeqCst), "nd idle");
        assert_eq!(super::nd_cached(&peer), Some(peer_mac), "peer cached");
        super::capture_begin();
        super::with_tcp(|tab| {
            let s = tab[cli].as_mut().unwrap();
            assert_eq!(s.unacked.len(), 1);
            s.unacked[0].2 = 0;
        });
        super::retransmit_forced();
        let again = super::capture_take();
        super::rtx_hold(false);
        assert_eq!(again.len(), 1, "rto resends");
        assert_eq!(&again[0][74..], b"xy");
        assert!(sum_ok(&again[0], 6));
        super::capture_begin();
        tcp_close(cli);
        let fins = super::capture_take();
        assert_eq!(fins.len(), 1, "close sends FIN");
        assert_eq!(fins[0][67] & TH_FIN, TH_FIN);
        assert!(sum_ok(&fins[0], 6));

        // Девятый сосед вытесняет самый старый.
        super::attach(mac);
        for i in 1..=8u8 {
            let mut ip = [0u8; 16];
            ip[0] = 0xfe;
            ip[1] = 0x80;
            ip[14] = 1;
            ip[15] = i;
            super::nd_learn(ip, [i, 0, 0, 0, 0, 1]);
        }
        let mut first = [0u8; 16];
        first[0] = 0xfe;
        first[1] = 0x80;
        first[14] = 1;
        first[15] = 1;
        let mut ninth = first;
        ninth[15] = 9;
        super::nd_learn(ninth, [9, 0, 0, 0, 0, 1]);
        assert!(super::nd_cached(&first).is_none());
        assert_eq!(super::nd_cached(&ninth).map(|m| m[0]), Some(9));

        if let Some(saved) = real {
            super::attach(saved);
        } else {
            super::with_link(|link| {
                link.up = false;
                link.mac = [0; 6];
                link.ll = UNSPEC;
            });
        }
        serial_println!("[ok]");
    }
}
