//! `AF_NETLINK` / `NETLINK_ROUTE`.
//!
//! Ответ собирается из того, что стек уже держит, а не из выдуманной таблицы.
//! `lo` есть всегда: `127.0.0.1/8` и `::1/128`. `eth0` появляется только вместе
//! с поднятой картой virtio: её MAC, IPv4 после DHCP и `fe80::/64`, если
//! link-local посчитан. Другого интерфейса и глобального IPv6 нет.
//!
//! `RTM_GETLINK` и `RTM_GETADDR` с `NLM_F_DUMP` идут пачкой `NLM_F_MULTI` и
//! кончаются `NLMSG_DONE`. Без дампа `RTM_GETLINK` отдаёт один интерфейс по
//! индексу или по `IFLA_IFNAME`. `NLM_F_ACK` на дампе второго ответа не
//! добавляет. На одиночном `GETLINK` с `NLM_F_ACK` следом идёт `NLMSG_ERROR`
//! с нулём.
//!
//! Запись адреса, удаление, маршрут и любой другой тип — `NLMSG_ERROR` с
//! `-EOPNOTSUPP`. Группы привязки нет: ненулевая маска — `EOPNOTSUPP`,
//! уведомления не шлются. Бит `IFF_MULTICAST` у `eth0` значит только, что
//! среда Ethernet. Список групп и фильтр карты здесь не появляются.

use alloc::vec;
use alloc::vec::Vec;
use spin::Mutex;

pub const REQ_MAX: usize = 4096;

pub const EAGAIN: i32 = 11;
pub const EBADF: i32 = 9;
pub const ENODEV: i32 = 19;
pub const EINVAL: i32 = 22;
pub const ENFILE: i32 = 23;
pub const EDESTADDRREQ: i32 = 89;
pub const EMSGSIZE: i32 = 90;
pub const EPROTONOSUPPORT: i32 = 93;
pub const EOPNOTSUPP: i32 = 95;
pub const EAFNOSUPPORT: i32 = 97;
pub const EADDRINUSE: i32 = 98;
pub const ENOBUFS: i32 = 105;
pub const ECONNREFUSED: i32 = 111;

const AF_NETLINK: u16 = 16;
const SOCK_DGRAM: u8 = 2;
const SOCK_RAW: u8 = 3;

const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLMSG_NOOP: u16 = 1;

const NLM_F_REQUEST: u16 = 1;
const NLM_F_MULTI: u16 = 2;
const NLM_F_ACK: u16 = 4;
const NLM_F_DUMP: u16 = 0x300;

const RTM_NEWLINK: u16 = 16;
const RTM_GETLINK: u16 = 18;
const RTM_NEWADDR: u16 = 20;
const RTM_GETADDR: u16 = 22;
const RTM_GETROUTE: u16 = 26;

const ARPHRD_ETHER: u16 = 1;
const ARPHRD_LOOPBACK: u16 = 772;

const IFF_UP: u32 = 0x1;
const IFF_BROADCAST: u32 = 0x2;
const IFF_LOOPBACK: u32 = 0x8;
const IFF_RUNNING: u32 = 0x40;
const IFF_MULTICAST: u32 = 0x1000;

const IFLA_ADDRESS: u16 = 1;
const IFLA_BROADCAST: u16 = 2;
const IFLA_IFNAME: u16 = 3;
const IFLA_MTU: u16 = 4;
const IFLA_OPERSTATE: u16 = 16;

const IF_OPER_UP: u8 = 6;

const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const IFA_LABEL: u16 = 3;
const IFA_BROADCAST: u16 = 4;
const IFA_FLAGS: u16 = 8;
const IFA_F_PERMANENT: u32 = 0x80;

const RT_SCOPE_UNIVERSE: u8 = 0;
const RT_SCOPE_LINK: u8 = 253;
const RT_SCOPE_HOST: u8 = 254;

const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;

/// Потолок датаграммы петли. Больше `lo` не принимает, поэтому MTU не 64 КиБ.
const LO_MTU: u32 = 4096;
const ETH_MTU: u32 = 1500;
const IF_LO: u32 = 1;
const IF_ETH: u32 = 2;

const SOCKS: usize = 16;
const QCAP: usize = 16;
/// Худший дамп: два интерфейса, четыре адреса и два `NLMSG_DONE`.
const DUMP_SLOTS: usize = 8;

struct Sock {
    refs: u8,
    port: u32,
    kind: u8,
    nonblock: bool,
    peer: Option<u32>,
    q: Vec<Vec<u8>>,
}

static TAB: Mutex<[Option<Sock>; SOCKS]> = Mutex::new([
    None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
]);
static NEXT_PORT: Mutex<u32> = Mutex::new(1);

fn with_tab<R>(f: impl FnOnce(&mut [Option<Sock>; SOCKS]) -> R) -> R {
    x86_64::instructions::interrupts::without_interrupts(|| f(&mut TAB.lock()))
}

pub fn open(kind: u8, proto: u32, nonblock: bool) -> Result<usize, i32> {
    // Только NETLINK_ROUTE. SOCK_DGRAM и SOCK_RAW для netlink одинаковы.
    if proto != 0 || (kind != SOCK_DGRAM && kind != SOCK_RAW) {
        return Err(EPROTONOSUPPORT);
    }
    with_tab(|tab| {
        for (i, slot) in tab.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(Sock {
                    refs: 1,
                    port: 0,
                    kind,
                    nonblock,
                    peer: None,
                    q: Vec::new(),
                });
                return Ok(i);
            }
        }
        Err(ENFILE)
    })
}

pub fn addref(id: usize) {
    with_tab(|tab| {
        if let Some(Some(s)) = tab.get_mut(id) {
            s.refs = s.refs.saturating_add(1);
        }
    });
}

pub fn close(id: usize) {
    with_tab(|tab| {
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

pub fn nonblock(id: usize) -> bool {
    with_tab(|tab| {
        tab.get(id)
            .and_then(|s| s.as_ref())
            .map(|s| s.nonblock)
            .unwrap_or(false)
    })
}

pub fn sock_type(id: usize) -> Result<i32, i32> {
    with_tab(|tab| {
        tab.get(id)
            .and_then(|s| s.as_ref())
            .map(|s| s.kind as i32)
            .ok_or(EBADF)
    })
}

pub fn pending(id: usize) -> bool {
    with_tab(|tab| {
        tab.get(id)
            .and_then(|s| s.as_ref())
            .map(|s| !s.q.is_empty())
            .unwrap_or(false)
    })
}

pub fn writable(id: usize) -> bool {
    with_tab(|tab| {
        tab.get(id)
            .and_then(|s| s.as_ref())
            .map(|s| s.q.len() + DUMP_SLOTS <= QCAP)
            .unwrap_or(false)
    })
}

pub fn port_of(id: usize) -> Result<u32, i32> {
    with_tab(|tab| {
        tab.get(id)
            .and_then(|s| s.as_ref())
            .map(|s| s.port)
            .ok_or(EBADF)
    })
}

pub fn peer(id: usize) -> Result<Option<u32>, i32> {
    with_tab(|tab| {
        tab.get(id)
            .and_then(|s| s.as_ref())
            .map(|s| s.peer)
            .ok_or(EBADF)
    })
}

pub fn bind(id: usize, sa: &[u8]) -> Result<(), i32> {
    let (pid, groups) = parse_sa(sa)?;
    if groups != 0 {
        return Err(EOPNOTSUPP);
    }
    with_tab(|tab| {
        if tab.get(id).and_then(|s| s.as_ref()).is_none() {
            return Err(EBADF);
        }
        if tab[id].as_ref().unwrap().port != 0 {
            return Err(EINVAL);
        }
        let port = claim_port(tab, pid)?;
        tab[id].as_mut().unwrap().port = port;
        Ok(())
    })
}

pub fn connect(id: usize, sa: &[u8]) -> Result<(), i32> {
    let (pid, groups) = parse_sa(sa)?;
    if groups != 0 {
        return Err(EOPNOTSUPP);
    }
    // Чужому сокету кадры не перекладываем: принимается только ядро, pid 0.
    if pid != 0 {
        return Err(ECONNREFUSED);
    }
    with_tab(|tab| {
        ensure_port(tab, id)?;
        tab[id].as_mut().unwrap().peer = Some(0);
        Ok(())
    })
}

/// `dest == None` — уже соединённый сокет, иначе pid назначения.
/// Ненулевой pid — не ядро, такого сокета нет.
pub fn send(id: usize, data: &[u8], dest: Option<u32>) -> Result<usize, i32> {
    if data.len() > REQ_MAX {
        return Err(EMSGSIZE);
    }
    if data.is_empty() {
        return Err(EINVAL);
    }
    if let Some(pid) = dest {
        if pid != 0 {
            return Err(ECONNREFUSED);
        }
    }
    with_tab(|tab| {
        let peer = match tab.get(id).and_then(|s| s.as_ref()) {
            Some(s) => s.peer,
            None => return Err(EBADF),
        };
        if dest.is_none() && peer != Some(0) {
            return Err(EDESTADDRREQ);
        }
        ensure_port(tab, id)?;
        Ok(())
    })?;
    // Снимок вне лока сокета: тот не берёт IFACE/LINK, и наоборот.
    let v4 = crate::net::iface_snap();
    let v6 = crate::net6::ll_snap();
    let replies = build_replies(data, &v4, &v6)?;
    with_tab(|tab| {
        let Some(s) = tab.get_mut(id).and_then(|s| s.as_mut()) else {
            return Err(EBADF);
        };
        if s.q.len() + replies.len() > QCAP {
            return Err(ENOBUFS);
        }
        for msg in replies {
            s.q.push(msg);
        }
        Ok(data.len())
    })
}

pub fn recv(id: usize, buf: &mut [u8]) -> Result<usize, i32> {
    if buf.is_empty() {
        return Ok(0);
    }
    with_tab(|tab| {
        let Some(s) = tab.get_mut(id).and_then(|s| s.as_mut()) else {
            return Err(EBADF);
        };
        if s.q.is_empty() {
            return Err(EAGAIN);
        }
        let msg = s.q.remove(0);
        let n = msg.len().min(buf.len());
        buf[..n].copy_from_slice(&msg[..n]);
        Ok(n)
    })
}

fn parse_sa(sa: &[u8]) -> Result<(u32, u32), i32> {
    if sa.len() < 12 {
        return Err(EINVAL);
    }
    let family = u16::from_le_bytes([sa[0], sa[1]]);
    if family != AF_NETLINK {
        return Err(EAFNOSUPPORT);
    }
    let pid = u32::from_le_bytes(sa[4..8].try_into().unwrap());
    let groups = u32::from_le_bytes(sa[8..12].try_into().unwrap());
    Ok((pid, groups))
}

/// `pid == 0` — выдать свободный. Иначе занять запрошенный, если он свободен.
fn claim_port(tab: &[Option<Sock>; SOCKS], pid: u32) -> Result<u32, i32> {
    if pid == 0 {
        return alloc_port(tab);
    }
    if tab.iter().flatten().any(|s| s.port == pid) {
        return Err(EADDRINUSE);
    }
    Ok(pid)
}

fn ensure_port(tab: &mut [Option<Sock>; SOCKS], id: usize) -> Result<u32, i32> {
    if tab.get(id).and_then(|s| s.as_ref()).is_none() {
        return Err(EBADF);
    }
    if tab[id].as_ref().unwrap().port == 0 {
        let port = alloc_port(tab)?;
        tab[id].as_mut().unwrap().port = port;
    }
    Ok(tab[id].as_ref().unwrap().port)
}

fn alloc_port(tab: &[Option<Sock>; SOCKS]) -> Result<u32, i32> {
    // Тот же порядок, что у UDP: сначала таблица, потом счётчик.
    let mut next = NEXT_PORT.lock();
    for _ in 0..65536 {
        let port = *next;
        *next = if port >= 0xffff_fffe { 1 } else { port + 1 };
        if port != 0 && !tab.iter().flatten().any(|s| s.port == port) {
            return Ok(port);
        }
    }
    Err(EADDRINUSE)
}

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

fn build_replies(
    data: &[u8],
    v4: &crate::net::IfaceSnap,
    v6: &crate::net6::LlSnap,
) -> Result<Vec<Vec<u8>>, i32> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off < data.len() {
        if data.len() - off < 16 {
            return Err(EINVAL);
        }
        let len = u32::from_le_bytes(data[off..off + 4].try_into().unwrap()) as usize;
        if len < 16 || off + len > data.len() {
            return Err(EINVAL);
        }
        let msg = &data[off..off + len];
        let ty = u16::from_le_bytes(msg[4..6].try_into().unwrap());
        let flags = u16::from_le_bytes(msg[6..8].try_into().unwrap());
        let seq = u32::from_le_bytes(msg[8..12].try_into().unwrap());
        if ty != NLMSG_NOOP {
            if flags & NLM_F_REQUEST == 0 {
                out.push(error_msg(seq, -EINVAL, msg));
            } else {
                answer(&mut out, ty, flags, seq, msg, v4, v6);
            }
        }
        let next = off.saturating_add(align4(len));
        if next <= off {
            return Err(EINVAL);
        }
        if next >= data.len() {
            break;
        }
        off = next;
    }
    Ok(out)
}

fn answer(
    out: &mut Vec<Vec<u8>>,
    ty: u16,
    flags: u16,
    seq: u32,
    msg: &[u8],
    v4: &crate::net::IfaceSnap,
    v6: &crate::net6::LlSnap,
) {
    let dump = flags & NLM_F_DUMP == NLM_F_DUMP;
    match ty {
        RTM_GETLINK => answer_link(out, dump, flags, seq, msg, v4, v6),
        RTM_GETADDR => answer_addr(out, dump, seq, msg, v4, v6),
        // Маршрута в стеке нет как объекта. Пустой дамп сказал бы «маршрутов нет».
        RTM_GETROUTE => out.push(error_msg(seq, -EOPNOTSUPP, msg)),
        _ => out.push(error_msg(seq, -EOPNOTSUPP, msg)),
    }
}

struct LinkInfo {
    index: u32,
    name: &'static str,
    typ: u16,
    flags: u32,
    mtu: u32,
    mac: Option<[u8; 6]>,
}

struct AddrInfo {
    index: u32,
    family: u8,
    prefix: u8,
    scope: u8,
    flags: u32,
    bytes: Vec<u8>,
    label: Option<&'static str>,
    bcast: Option<[u8; 4]>,
}

fn eth_mac(v4: &crate::net::IfaceSnap, v6: &crate::net6::LlSnap) -> Option<[u8; 6]> {
    if v4.up {
        Some(v4.mac)
    } else if v6.up {
        Some(v6.mac)
    } else {
        None
    }
}

fn links(v4: &crate::net::IfaceSnap, v6: &crate::net6::LlSnap) -> Vec<LinkInfo> {
    let mut out = vec![LinkInfo {
        index: IF_LO,
        name: "lo",
        typ: ARPHRD_LOOPBACK,
        flags: IFF_UP | IFF_LOOPBACK | IFF_RUNNING,
        mtu: LO_MTU,
        mac: None,
    }];
    if let Some(mac) = eth_mac(v4, v6) {
        out.push(LinkInfo {
            index: IF_ETH,
            name: "eth0",
            typ: ARPHRD_ETHER,
            flags: IFF_UP | IFF_BROADCAST | IFF_RUNNING | IFF_MULTICAST,
            mtu: ETH_MTU,
            mac: Some(mac),
        });
    }
    out
}

fn prefix_len(mask: u32) -> u8 {
    let ones = mask.leading_ones();
    if ones == 0 || ones + mask.trailing_zeros() != 32 {
        32
    } else {
        ones as u8
    }
}

fn addresses(v4: &crate::net::IfaceSnap, v6: &crate::net6::LlSnap) -> Vec<AddrInfo> {
    let mut lo6 = vec![0u8; 16];
    lo6[15] = 1;
    let mut out = vec![
        AddrInfo {
            index: IF_LO,
            family: AF_INET,
            prefix: 8,
            scope: RT_SCOPE_HOST,
            flags: IFA_F_PERMANENT,
            bytes: vec![127, 0, 0, 1],
            label: Some("lo"),
            bcast: Some([127, 255, 255, 255]),
        },
        AddrInfo {
            index: IF_LO,
            family: AF_INET6,
            prefix: 128,
            scope: RT_SCOPE_HOST,
            flags: IFA_F_PERMANENT,
            bytes: lo6,
            label: None,
            bcast: None,
        },
    ];
    if eth_mac(v4, v6).is_none() {
        return out;
    }
    if v4.up && v4.ip != 0 {
        out.push(AddrInfo {
            index: IF_ETH,
            family: AF_INET,
            prefix: prefix_len(v4.mask),
            scope: RT_SCOPE_UNIVERSE,
            flags: IFA_F_PERMANENT,
            bytes: v4.ip.to_be_bytes().to_vec(),
            label: Some("eth0"),
            bcast: Some((v4.ip | !v4.mask).to_be_bytes()),
        });
    }
    if v6.up && v6.ll.iter().any(|b| *b != 0) {
        out.push(AddrInfo {
            index: IF_ETH,
            family: AF_INET6,
            prefix: 64,
            scope: RT_SCOPE_LINK,
            flags: IFA_F_PERMANENT,
            bytes: v6.ll.to_vec(),
            label: None,
            bcast: None,
        });
    }
    out
}

fn answer_link(
    out: &mut Vec<Vec<u8>>,
    dump: bool,
    flags: u16,
    seq: u32,
    msg: &[u8],
    v4: &crate::net::IfaceSnap,
    v6: &crate::net6::LlSnap,
) {
    let all = links(v4, v6);
    if dump {
        for link in &all {
            out.push(link_msg(link, seq, NLM_F_MULTI));
        }
        out.push(done_msg(seq));
        return;
    }
    let index = if msg.len() >= 24 {
        i32::from_le_bytes(msg[20..24].try_into().unwrap())
    } else {
        0
    };
    let found = if index > 0 {
        all.iter().find(|l| l.index == index as u32)
    } else if let Some(name) = ifname_attr(msg) {
        all.iter().find(|l| l.name == name)
    } else {
        out.push(error_msg(seq, -EINVAL, msg));
        return;
    };
    match found {
        Some(link) => {
            out.push(link_msg(link, seq, 0));
            if flags & NLM_F_ACK != 0 {
                out.push(error_msg(seq, 0, msg));
            }
        }
        None => out.push(error_msg(seq, -ENODEV, msg)),
    }
}

fn answer_addr(
    out: &mut Vec<Vec<u8>>,
    dump: bool,
    seq: u32,
    msg: &[u8],
    v4: &crate::net::IfaceSnap,
    v6: &crate::net6::LlSnap,
) {
    // Точечный поиск одного адреса не делаем: пользователю нужен дамп.
    if !dump {
        out.push(error_msg(seq, -EINVAL, msg));
        return;
    }
    let (family, index) = if msg.len() >= 24 {
        let family = msg[16];
        let index = u32::from_le_bytes(msg[20..24].try_into().unwrap());
        (family, index)
    } else {
        (0, 0)
    };
    if family != 0 && family != AF_INET && family != AF_INET6 {
        out.push(error_msg(seq, -EAFNOSUPPORT, msg));
        return;
    }
    if index != 0 && index != IF_LO && !(index == IF_ETH && eth_mac(v4, v6).is_some()) {
        out.push(error_msg(seq, -ENODEV, msg));
        return;
    }
    for addr in addresses(v4, v6) {
        if index != 0 && addr.index != index {
            continue;
        }
        if family != 0 && addr.family != family {
            continue;
        }
        out.push(addr_msg(&addr, seq, NLM_F_MULTI));
    }
    out.push(done_msg(seq));
}

fn ifname_attr(msg: &[u8]) -> Option<&str> {
    if msg.len() < 32 {
        return None;
    }
    let mut off = 32usize;
    while off < msg.len() && msg.len() - off >= 4 {
        let alen = u16::from_le_bytes(msg[off..off + 2].try_into().unwrap()) as usize;
        if alen < 4 || off + alen > msg.len() {
            return None;
        }
        let aty = u16::from_le_bytes(msg[off + 2..off + 4].try_into().unwrap()) & 0x3fff;
        if aty == IFLA_IFNAME {
            let data = &msg[off + 4..off + alen];
            let end = data.iter().position(|b| *b == 0).unwrap_or(data.len());
            return core::str::from_utf8(&data[..end]).ok();
        }
        let step = align4(alen);
        if step == 0 {
            return None;
        }
        off += step;
    }
    None
}

fn nlmsg(ty: u16, flags: u16, seq: u32, payload: &[u8]) -> Vec<u8> {
    let len = 16 + payload.len();
    let mut v = Vec::with_capacity(len);
    v.extend_from_slice(&(len as u32).to_le_bytes());
    v.extend_from_slice(&ty.to_le_bytes());
    v.extend_from_slice(&flags.to_le_bytes());
    v.extend_from_slice(&seq.to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes());
    v.extend_from_slice(payload);
    v
}

fn attr(ty: u16, data: &[u8]) -> Vec<u8> {
    let len = 4 + data.len();
    let mut v = Vec::with_capacity(align4(len));
    v.extend_from_slice(&(len as u16).to_le_bytes());
    v.extend_from_slice(&ty.to_le_bytes());
    v.extend_from_slice(data);
    while v.len() % 4 != 0 {
        v.push(0);
    }
    v
}

fn cstr(name: &str) -> Vec<u8> {
    let mut v = name.as_bytes().to_vec();
    v.push(0);
    v
}

fn link_msg(link: &LinkInfo, seq: u32, flags: u16) -> Vec<u8> {
    let mut payload = vec![0u8; 16];
    payload[2..4].copy_from_slice(&link.typ.to_le_bytes());
    payload[4..8].copy_from_slice(&(link.index as i32).to_le_bytes());
    payload[8..12].copy_from_slice(&link.flags.to_le_bytes());
    payload[12..16].copy_from_slice(&0xffff_ffffu32.to_le_bytes());
    payload.extend(attr(IFLA_IFNAME, &cstr(link.name)));
    payload.extend(attr(IFLA_MTU, &link.mtu.to_le_bytes()));
    payload.extend(attr(IFLA_OPERSTATE, &[IF_OPER_UP]));
    if let Some(mac) = link.mac {
        payload.extend(attr(IFLA_ADDRESS, &mac));
        payload.extend(attr(IFLA_BROADCAST, &[0xff; 6]));
    }
    nlmsg(RTM_NEWLINK, flags, seq, &payload)
}

fn addr_msg(addr: &AddrInfo, seq: u32, flags: u16) -> Vec<u8> {
    let mut payload = vec![0u8; 8];
    payload[0] = addr.family;
    payload[1] = addr.prefix;
    payload[2] = addr.flags as u8;
    payload[3] = addr.scope;
    payload[4..8].copy_from_slice(&addr.index.to_le_bytes());
    payload.extend(attr(IFA_ADDRESS, &addr.bytes));
    if addr.family == AF_INET {
        payload.extend(attr(IFA_LOCAL, &addr.bytes));
        if let Some(b) = addr.bcast {
            payload.extend(attr(IFA_BROADCAST, &b));
        }
        if let Some(label) = addr.label {
            payload.extend(attr(IFA_LABEL, &cstr(label)));
        }
    }
    payload.extend(attr(IFA_FLAGS, &addr.flags.to_le_bytes()));
    nlmsg(RTM_NEWADDR, flags, seq, &payload)
}

fn done_msg(seq: u32) -> Vec<u8> {
    nlmsg(NLMSG_DONE, NLM_F_MULTI, seq, &0i32.to_le_bytes())
}

fn error_msg(seq: u32, err: i32, req: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(20);
    payload.extend_from_slice(&err.to_le_bytes());
    let n = req.len().min(16);
    payload.extend_from_slice(&req[..n]);
    if n < 16 {
        payload.extend(core::iter::repeat(0).take(16 - n));
    }
    nlmsg(NLMSG_ERROR, 0, seq, &payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use crate::{serial_print, serial_println};

    fn sa(pid: u32, groups: u32) -> [u8; 12] {
        let mut raw = [0u8; 12];
        raw[0..2].copy_from_slice(&AF_NETLINK.to_le_bytes());
        raw[4..8].copy_from_slice(&pid.to_le_bytes());
        raw[8..12].copy_from_slice(&groups.to_le_bytes());
        raw
    }

    fn req(ty: u16, flags: u16, seq: u32, payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        let len = 16 + payload.len();
        v.extend_from_slice(&(len as u32).to_le_bytes());
        v.extend_from_slice(&ty.to_le_bytes());
        v.extend_from_slice(&flags.to_le_bytes());
        v.extend_from_slice(&seq.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(payload);
        v
    }

    fn drain(id: usize) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let mut buf = [0u8; 2048];
        loop {
            match recv(id, &mut buf) {
                Ok(0) => panic!("empty recv"),
                Ok(n) => out.push(buf[..n].to_vec()),
                Err(EAGAIN) => return out,
                Err(e) => panic!("recv {e}"),
            }
        }
    }

    fn hdr(msg: &[u8]) -> (u16, u16, u32, &[u8]) {
        assert!(msg.len() >= 16, "short nlmsg");
        let len = u32::from_le_bytes(msg[0..4].try_into().unwrap()) as usize;
        assert_eq!(len, msg.len(), "nlmsg_len");
        let ty = u16::from_le_bytes(msg[4..6].try_into().unwrap());
        let flags = u16::from_le_bytes(msg[6..8].try_into().unwrap());
        let seq = u32::from_le_bytes(msg[8..12].try_into().unwrap());
        let pid = u32::from_le_bytes(msg[12..16].try_into().unwrap());
        assert_eq!(pid, 0, "kernel pid");
        (ty, flags, seq, &msg[16..])
    }

    fn attr_get<'a>(buf: &'a [u8], want: u16) -> Option<&'a [u8]> {
        let mut off = 0usize;
        while off < buf.len() && buf.len() - off >= 4 {
            let alen = u16::from_le_bytes(buf[off..off + 2].try_into().unwrap()) as usize;
            if alen < 4 || off + alen > buf.len() {
                return None;
            }
            let ty = u16::from_le_bytes(buf[off + 2..off + 4].try_into().unwrap()) & 0x3fff;
            if ty == want {
                return Some(&buf[off + 4..off + alen]);
            }
            let step = (alen + 3) & !3;
            if step == 0 {
                return None;
            }
            off += step;
        }
        None
    }

    fn cstr_eq(data: &[u8], name: &str) -> bool {
        let end = data.iter().position(|b| *b == 0).unwrap_or(data.len());
        &data[..end] == name.as_bytes()
    }

    #[test_case]
    fn netlink_route_dumps_links_and_addresses() {
        serial_print!("test netlink_route_dumps_links_and_addresses... ");
        assert_eq!(open(1, 0, true), Err(EPROTONOSUPPORT), "stream");
        assert_eq!(open(SOCK_RAW, 4, true), Err(EPROTONOSUPPORT), "family");

        let id = open(SOCK_RAW, 0, true).expect("open");
        assert_eq!(bind(id, &sa(0, 1)), Err(EOPNOTSUPP), "groups");
        assert_eq!(port_of(id).unwrap(), 0, "unbound");
        assert_eq!(send(id, &req(RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP, 1, &[]), None), Err(EDESTADDRREQ));
        bind(id, &sa(0x51, 0)).unwrap();
        assert_eq!(port_of(id).unwrap(), 0x51);
        assert_eq!(bind(id, &sa(0, 0)), Err(EINVAL), "second bind");

        let other = open(SOCK_DGRAM, 0, true).expect("open 2");
        assert_eq!(bind(other, &sa(0x51, 0)), Err(EADDRINUSE));
        assert_eq!(connect(other, &sa(4, 0)), Err(ECONNREFUSED));
        connect(other, &sa(0, 0)).unwrap();
        assert_eq!(peer(other).unwrap(), Some(0));
        assert_ne!(port_of(other).unwrap(), 0, "autobind");

        let snap = crate::net::iface_snap();
        let ll = crate::net6::ll_snap();
        assert!(snap.up, "virtio link");
        assert!(ll.up, "link-local");
        assert_ne!(snap.ip, 0, "dhcp address");
        assert_eq!(ll.ll[0], 0xfe);
        assert_eq!(ll.mac, snap.mac);

        send(id, &req(RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP, 7, &[]), Some(0)).unwrap();
        let msgs = drain(id);
        assert!(msgs.len() >= 2, "link dump");
        let mut names = Vec::new();
        for (i, msg) in msgs.iter().enumerate() {
            let (ty, flags, seq, payload) = hdr(msg);
            assert_eq!(seq, 7);
            if i + 1 == msgs.len() {
                assert_eq!(ty, NLMSG_DONE);
                assert_ne!(flags & NLM_F_MULTI, 0);
                assert_eq!(i32::from_le_bytes(payload[..4].try_into().unwrap()), 0);
                continue;
            }
            assert_eq!(ty, RTM_NEWLINK);
            assert_ne!(flags & NLM_F_MULTI, 0);
            assert_eq!(payload.len() >= 16, true);
            let index = i32::from_le_bytes(payload[4..8].try_into().unwrap());
            let iflags = u32::from_le_bytes(payload[8..12].try_into().unwrap());
            let change = u32::from_le_bytes(payload[12..16].try_into().unwrap());
            assert_eq!(change, 0xffff_ffff);
            let name = attr_get(&payload[16..], IFLA_IFNAME).expect("ifname");
            let mtu = u32::from_le_bytes(attr_get(&payload[16..], IFLA_MTU).unwrap()[..4].try_into().unwrap());
            let oper = attr_get(&payload[16..], IFLA_OPERSTATE).unwrap()[0];
            assert_eq!(oper, IF_OPER_UP);
            if cstr_eq(name, "lo") {
                assert_eq!(index, 1);
                assert_eq!(u16::from_le_bytes(payload[2..4].try_into().unwrap()), ARPHRD_LOOPBACK);
                assert_eq!(iflags, IFF_UP | IFF_LOOPBACK | IFF_RUNNING);
                assert_eq!(mtu, LO_MTU);
                assert!(attr_get(&payload[16..], IFLA_ADDRESS).is_none());
            } else if cstr_eq(name, "eth0") {
                assert_eq!(index, 2);
                assert_eq!(u16::from_le_bytes(payload[2..4].try_into().unwrap()), ARPHRD_ETHER);
                assert_eq!(iflags, IFF_UP | IFF_BROADCAST | IFF_RUNNING | IFF_MULTICAST);
                assert_eq!(mtu, ETH_MTU);
                let mac = attr_get(&payload[16..], IFLA_ADDRESS).unwrap();
                assert_eq!(mac, &snap.mac);
                assert_eq!(attr_get(&payload[16..], IFLA_BROADCAST).unwrap(), &[0xff; 6]);
            } else {
                panic!("unexpected link");
            }
            names.push(index);
        }
        assert_eq!(names, vec![1, 2]);

        let mut body = vec![0u8; 8];
        body[0] = AF_INET6;
        send(id, &req(RTM_GETADDR, NLM_F_REQUEST | NLM_F_DUMP, 8, &body), Some(0)).unwrap();
        let v6 = drain(id);
        let mut v6_addrs = Vec::new();
        for (i, msg) in v6.iter().enumerate() {
            let (ty, flags, seq, payload) = hdr(msg);
            assert_eq!(seq, 8);
            if i + 1 == v6.len() {
                assert_eq!(ty, NLMSG_DONE);
                assert_ne!(flags & NLM_F_MULTI, 0);
                continue;
            }
            assert_eq!(ty, RTM_NEWADDR);
            assert_eq!(payload[0], AF_INET6);
            let addr = attr_get(&payload[8..], IFA_ADDRESS).unwrap();
            assert_eq!(addr.len(), 16);
            assert_ne!(addr[0], 0x20, "no global");
            v6_addrs.push((payload[1], payload[3], u32::from_le_bytes(payload[4..8].try_into().unwrap()), addr.to_vec()));
        }
        assert_eq!(v6_addrs.len(), 2, "only ::1 and link-local");
        assert!(v6_addrs.iter().any(|a| a.0 == 128 && a.1 == RT_SCOPE_HOST && a.2 == 1 && a.3[15] == 1 && a.3[..15].iter().all(|b| *b == 0)));
        assert!(v6_addrs.iter().any(|a| a.0 == 64 && a.1 == RT_SCOPE_LINK && a.2 == 2 && a.3.as_slice() == &ll.ll[..]));

        body[0] = AF_INET;
        send(id, &req(RTM_GETADDR, NLM_F_REQUEST | NLM_F_DUMP, 4, &body), Some(0)).unwrap();
        let v4 = drain(id);
        let mut v4_addrs = Vec::new();
        for (i, msg) in v4.iter().enumerate() {
            let (ty, _, seq, payload) = hdr(msg);
            assert_eq!(seq, 4);
            if i + 1 == v4.len() {
                assert_eq!(ty, NLMSG_DONE);
                continue;
            }
            assert_eq!(ty, RTM_NEWADDR);
            assert_eq!(payload[0], AF_INET);
            assert_eq!(payload[2], IFA_F_PERMANENT as u8);
            let addr = attr_get(&payload[8..], IFA_ADDRESS).unwrap();
            let local = attr_get(&payload[8..], IFA_LOCAL).unwrap();
            assert_eq!(addr, local);
            assert_eq!(addr.len(), 4);
            let flags = u32::from_le_bytes(attr_get(&payload[8..], IFA_FLAGS).unwrap()[..4].try_into().unwrap());
            assert_eq!(flags, IFA_F_PERMANENT);
            v4_addrs.push((
                payload[1],
                payload[3],
                u32::from_le_bytes(payload[4..8].try_into().unwrap()),
                addr.to_vec(),
                attr_get(&payload[8..], IFA_LABEL).unwrap().to_vec(),
            ));
        }
        assert_eq!(v4_addrs.len(), 2);
        assert!(v4_addrs.iter().any(|a| a.0 == 8 && a.1 == RT_SCOPE_HOST && a.2 == 1 && a.3.as_slice() == [127, 0, 0, 1] && cstr_eq(&a.4, "lo")));
        let expect = snap.ip.to_be_bytes();
        let prefix = prefix_len(snap.mask);
        assert!(v4_addrs.iter().any(|a| {
            a.0 == prefix && a.1 == RT_SCOPE_UNIVERSE && a.2 == 2 && a.3.as_slice() == expect && cstr_eq(&a.4, "eth0")
        }));

        send(id, &req(RTM_GETROUTE, NLM_F_REQUEST | NLM_F_DUMP, 9, &[]), Some(0)).unwrap();
        let err = drain(id);
        assert_eq!(err.len(), 1);
        let (ty, flags, seq, payload) = hdr(&err[0]);
        assert_eq!(ty, NLMSG_ERROR);
        assert_eq!(flags, 0);
        assert_eq!(seq, 9);
        assert_eq!(i32::from_le_bytes(payload[..4].try_into().unwrap()), -EOPNOTSUPP);
        assert_eq!(u16::from_le_bytes(payload[8..10].try_into().unwrap()), RTM_GETROUTE);

        send(id, &req(RTM_NEWADDR, NLM_F_REQUEST, 10, &[]), Some(0)).unwrap();
        let err = drain(id);
        assert_eq!(i32::from_le_bytes(hdr(&err[0]).3[..4].try_into().unwrap()), -EOPNOTSUPP);

        send(id, &req(RTM_GETLINK, NLM_F_DUMP, 11, &[]), Some(0)).unwrap();
        let err = drain(id);
        assert_eq!(i32::from_le_bytes(hdr(&err[0]).3[..4].try_into().unwrap()), -EINVAL);

        let mut bad = req(RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP, 12, &[]);
        bad.push(0);
        assert_eq!(send(id, &bad, Some(0)), Err(EINVAL));
        assert!(!pending(id));

        let mut info = vec![0u8; 16];
        info[4..8].copy_from_slice(&7i32.to_le_bytes());
        send(id, &req(RTM_GETLINK, NLM_F_REQUEST, 13, &info), Some(0)).unwrap();
        let err = drain(id);
        assert_eq!(i32::from_le_bytes(hdr(&err[0]).3[..4].try_into().unwrap()), -ENODEV);

        let mut named = vec![0u8; 16];
        let raw_name = b"lo\0";
        let alen = 4 + raw_name.len();
        named.extend_from_slice(&(alen as u16).to_le_bytes());
        named.extend_from_slice(&IFLA_IFNAME.to_le_bytes());
        named.extend_from_slice(raw_name);
        named.push(0);
        send(id, &req(RTM_GETLINK, NLM_F_REQUEST | NLM_F_ACK, 14, &named), Some(0)).unwrap();
        let one = drain(id);
        assert_eq!(one.len(), 2, "link plus ack");
        let (ty, flags, seq, payload) = hdr(&one[0]);
        assert_eq!(ty, RTM_NEWLINK);
        assert_eq!(flags & NLM_F_MULTI, 0);
        assert_eq!(seq, 14);
        assert!(cstr_eq(attr_get(&payload[16..], IFLA_IFNAME).unwrap(), "lo"));
        let (ty, _, seq, payload) = hdr(&one[1]);
        assert_eq!(ty, NLMSG_ERROR);
        assert_eq!(seq, 14);
        assert_eq!(i32::from_le_bytes(payload[..4].try_into().unwrap()), 0);

        body[0] = 99;
        send(id, &req(RTM_GETADDR, NLM_F_REQUEST | NLM_F_DUMP, 15, &body), Some(0)).unwrap();
        let err = drain(id);
        assert_eq!(i32::from_le_bytes(hdr(&err[0]).3[..4].try_into().unwrap()), -EAFNOSUPPORT);

        send(id, &req(RTM_GETADDR, NLM_F_REQUEST, 16, &[]), Some(0)).unwrap();
        let err = drain(id);
        assert_eq!(i32::from_le_bytes(hdr(&err[0]).3[..4].try_into().unwrap()), -EINVAL);

        let mut both = req(NLMSG_NOOP, NLM_F_REQUEST, 1, &[]);
        both.extend(req(RTM_GETROUTE, NLM_F_REQUEST, 17, &[]));
        send(other, &both, None).unwrap();
        let err = drain(other);
        assert_eq!(err.len(), 1);
        assert_eq!(hdr(&err[0]).2, 17);
        assert_eq!(i32::from_le_bytes(hdr(&err[0]).3[..4].try_into().unwrap()), -EOPNOTSUPP);

        addref(id);
        close(id);
        assert_eq!(port_of(id).unwrap(), 0x51, "ref remains");
        close(id);
        assert_eq!(port_of(id), Err(EBADF));
        close(other);
        assert!(!pending(other));

        serial_println!("[ok]");
    }
}
