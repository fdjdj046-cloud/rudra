#!/usr/bin/env python3
"""Собрать rudra-1.0.0.img: 16 МиБ загрузчик + 16 МиБ ext2.

Это raw-образ, не ISO. ext2 начинается с байта 16 МиБ.

Раскладка ext2 (rev 1, блок 4096, inode 128, одна группа, только FILETYPE):
  блок 0  суперблок на смещении 1024
  блок 1  таблица дескрипторов групп
  блок 2  bitmap блоков
  блок 3  bitmap inode
  блоки 4..19  таблица inode (512 * 128)
  дальше данные: /, /lost+found, /bin, busybox и ELF

Файл не больше (12 + 4096/4) * 4096 = 4243456 байт: 12 прямых и один
косвенный блок. Каталог — только прямые блоки.
"""
import hashlib
import os
import struct
import sys

BLOCK = 4096
BLOCKS = 4096
INODES = 512
INODE_SIZE = 128
BPG = BLOCK * 8  # 32768
FS_BYTES = BLOCK * BLOCKS
BOOT_RESERVE = 16 * 1024 * 1024
BB_BLOCK = 2
IB_BLOCK = 3
ITABLE = 4
ITABLE_BLOCKS = INODES * INODE_SIZE // BLOCK
FIRST_DATA = ITABLE + ITABLE_BLOCKS
FILE_MAX = (12 + BLOCK // 4) * BLOCK

FT_REG = 1
FT_DIR = 2
INO_ROOT = 2
S_IFREG = 0x81A4
S_IFDIR = 0x41ED

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def set_bit(buf, bit):
    buf[bit // 8] |= 1 << (bit % 8)


def ideal(name):
    return (8 + len(name) + 3) & ~3


def pack_dir(entries):
    buf = bytearray(BLOCK)
    off = 0
    for i, (ino, name, ft) in enumerate(entries):
        need = ideal(name)
        rec = (BLOCK - off) if i == len(entries) - 1 else need
        if rec < need or off + rec > BLOCK:
            raise SystemExit("dirent does not fit: %r" % name)
        struct.pack_into("<IHBB", buf, off, ino, rec, len(name), ft)
        buf[off + 8 : off + 8 + len(name)] = name
        off += rec
    return buf


def make_inode(mode, size, links, sectors, ptrs):
    raw = bytearray(INODE_SIZE)
    struct.pack_into("<H", raw, 0, mode)
    struct.pack_into("<I", raw, 4, size)
    struct.pack_into("<H", raw, 26, links)
    struct.pack_into("<I", raw, 28, sectors)
    for i, b in enumerate(ptrs):
        if b:
            struct.pack_into("<I", raw, 40 + i * 4, b)
    return raw


class Image:
    def __init__(self):
        self.img = bytearray(FS_BYTES)
        self.used = [False] * BLOCKS
        self.cursor = FIRST_DATA
        for b in range(FIRST_DATA):
            self.used[b] = True
        self.inodes = {}
        self.next_ino = 11

    def alloc(self):
        if self.cursor >= BLOCKS:
            raise SystemExit("ext2: no free blocks")
        b = self.cursor
        self.cursor += 1
        if self.used[b]:
            raise SystemExit("double alloc %d" % b)
        self.used[b] = True
        return b

    def write_block(self, b, data):
        if len(data) != BLOCK:
            raise SystemExit("block len")
        off = b * BLOCK
        self.img[off : off + BLOCK] = data

    def store_bytes(self, data):
        n = 0 if not data else (len(data) + BLOCK - 1) // BLOCK
        if n > 12 + BLOCK // 4:
            raise SystemExit("file exceeds %d bytes" % FILE_MAX)
        ptrs = [0] * 15
        chunks = []
        indirect = None
        allocated = 0
        for i in range(n):
            b = self.alloc()
            allocated += 1
            chunk = bytearray(BLOCK)
            start = i * BLOCK
            chunk[: len(data) - start] = data[start : start + BLOCK]
            chunks.append((b, chunk))
            if i < 12:
                ptrs[i] = b
            else:
                if indirect is None:
                    ib = self.alloc()
                    allocated += 1
                    indirect = bytearray(BLOCK)
                    ptrs[12] = ib
                    chunks.append((ib, indirect))
                struct.pack_into("<I", indirect, (i - 12) * 4, b)
        for b, chunk in chunks:
            self.write_block(b, chunk)
        return ptrs, allocated * (BLOCK // 512)

    def add_inode(self, ino, raw):
        self.inodes[ino] = raw

    def alloc_ino(self):
        ino = self.next_ino
        self.next_ino += 1
        if ino > INODES:
            raise SystemExit("ext2: no free inodes")
        return ino

    def add_dir(self, ino, parent, entries):
        block = self.alloc()
        items = [(ino, b".", FT_DIR), (parent, b"..", FT_DIR)] + entries
        self.write_block(block, pack_dir(items))
        self.add_inode(
            ino, make_inode(S_IFDIR, BLOCK, 2, BLOCK // 512, [block])
        )
        return ino

    def add_file(self, data):
        ino = self.alloc_ino()
        ptrs, sectors = self.store_bytes(data)
        self.add_inode(ino, make_inode(S_IFREG, len(data), 1, sectors, ptrs))
        return ino

    def finish(self, root_entries, used_dirs):
        # root nlink = 2 + число подкаталогов. Подкаталоги уже записаны.
        sub = sum(1 for _ino, _n, ft in root_entries if ft == FT_DIR)
        root = self.inodes[INO_ROOT]
        struct.pack_into("<H", root, 26, 2 + sub)
        for ino, raw in self.inodes.items():
            index = ino - 1
            per = BLOCK // INODE_SIZE
            block = ITABLE + index // per
            inner = (index % per) * INODE_SIZE
            off = block * BLOCK + inner
            self.img[off : off + INODE_SIZE] = raw

        bb = bytearray(BLOCK)
        for b in range(BLOCKS):
            if self.used[b]:
                set_bit(bb, b)
        for b in range(BLOCKS, BPG):
            set_bit(bb, b)
        ib = bytearray(BLOCK)
        for i in range(1, 11):
            set_bit(ib, i - 1)
        for ino in self.inodes:
            set_bit(ib, ino - 1)
        for i in range(INODES, BPG):
            set_bit(ib, i)
        self.write_block(BB_BLOCK, bb)
        self.write_block(IB_BLOCK, ib)

        free_blocks = sum(1 for b in range(BLOCKS) if not self.used[b])
        used_inos = set(range(1, 11)) | set(self.inodes)
        free_inodes = INODES - len(used_inos)

        sb = bytearray(1024)
        struct.pack_into("<I", sb, 0, INODES)
        struct.pack_into("<I", sb, 4, BLOCKS)
        struct.pack_into("<I", sb, 8, 0)
        struct.pack_into("<I", sb, 12, free_blocks)
        struct.pack_into("<I", sb, 16, free_inodes)
        struct.pack_into("<I", sb, 20, 0)  # first data block, блок > 1024
        struct.pack_into("<I", sb, 24, 2)  # log block size -> 4096
        struct.pack_into("<I", sb, 28, 2)  # log frag size
        struct.pack_into("<I", sb, 32, BPG)
        struct.pack_into("<I", sb, 36, BPG)
        struct.pack_into("<I", sb, 40, INODES)
        struct.pack_into("<H", sb, 54, 20)  # max mount count
        struct.pack_into("<H", sb, 56, 0xEF53)
        struct.pack_into("<H", sb, 58, 1)  # clean
        struct.pack_into("<H", sb, 60, 1)  # errors: continue
        struct.pack_into("<I", sb, 72, 0)  # creator OS: Linux
        struct.pack_into("<I", sb, 76, 1)  # rev 1
        struct.pack_into("<I", sb, 84, 11)  # first ino
        struct.pack_into("<H", sb, 88, INODE_SIZE)
        struct.pack_into("<I", sb, 96, 2)  # incompat: FILETYPE
        sb[104:120] = b"rudra-1.0.0-root"
        name = b"rudra-root"
        sb[120 : 120 + len(name)] = name
        self.img[1024 : 1024 + 1024] = sb

        gd = bytearray(BLOCK)
        struct.pack_into(
            "<IIIHHH",
            gd,
            0,
            BB_BLOCK,
            IB_BLOCK,
            ITABLE,
            free_blocks & 0xFFFF,
            free_inodes & 0xFFFF,
            used_dirs,
        )
        self.write_block(1, gd)
        return free_blocks, free_inodes


def read_inode(img, ino):
    index = ino - 1
    per = BLOCK // INODE_SIZE
    block = ITABLE + index // per
    inner = (index % per) * INODE_SIZE
    off = block * BLOCK + inner
    return img[off : off + INODE_SIZE]


def read_file_bytes(img, ino):
    inode = read_inode(img, ino)
    size = struct.unpack_from("<I", inode, 4)[0]
    if size == 0:
        return b""
    ptrs = [struct.unpack_from("<I", inode, 40 + i * 4)[0] for i in range(15)]
    n = (size + BLOCK - 1) // BLOCK
    out = bytearray()
    indirect = None
    for i in range(n):
        if i < 12:
            b = ptrs[i]
        else:
            if indirect is None:
                ib = ptrs[12]
                indirect = img[ib * BLOCK : (ib + 1) * BLOCK]
            b = struct.unpack_from("<I", indirect, (i - 12) * 4)[0]
        if b == 0 or b >= BLOCKS:
            raise SystemExit("bad block pointer ino %d" % ino)
        out += img[b * BLOCK : (b + 1) * BLOCK]
    return bytes(out[:size])


def list_dir(img, ino):
    data = read_file_bytes(img, ino)
    off = 0
    found = []
    while off + 8 <= len(data):
        child, rec, nl, ft = struct.unpack_from("<IHBB", data, off)
        if rec < 8 or off + rec > len(data):
            raise SystemExit("bad rec_len")
        name = data[off + 8 : off + 8 + nl]
        if child and name not in (b".", b".."):
            found.append((name.decode(), child, ft))
        off += rec
    return found


def lookup(img, path):
    ino = INO_ROOT
    if path == "/":
        return ino
    for part in path.split("/"):
        if not part:
            continue
        hit = None
        for name, child, _ft in list_dir(img, ino):
            if name == part:
                hit = child
                break
        if hit is None:
            raise SystemExit("missing %s" % path)
        ino = hit
    return ino


def build_fs_ordered():
    if FIRST_DATA != 20 or ITABLE_BLOCKS != 16:
        raise SystemExit("layout invariant broken")
    fs = Image()

    def load(path):
        with open(path, "rb") as f:
            data = f.read()
        if not data:
            raise SystemExit("empty %s" % path)
        return data

    payloads = []
    for name, path in [
        ("busybox", os.path.join(ROOT, "rootfs", "bin", "busybox")),
        ("shell.elf", os.path.join(ROOT, "target", "x86_64-unknown-none", "release", "shell")),
        ("hello.elf", os.path.join(ROOT, "target", "x86_64-unknown-none", "release", "hello")),
        ("counter.elf", os.path.join(ROOT, "target", "x86_64-unknown-none", "release", "counter")),
        ("fizzbuzz.elf", os.path.join(ROOT, "target", "x86_64-unknown-none", "release", "fizzbuzz")),
        ("threads.elf", os.path.join(ROOT, "target", "x86_64-unknown-none", "release", "threads")),
    ]:
        data = load(path)
        payloads.append((name, data))
        print("  /bin/%s %d bytes" % (name, len(data)))
    motd = load(os.path.join(ROOT, "rootfs", "motd.txt"))
    readme = load(os.path.join(ROOT, "rootfs", "readme.txt"))

    # Сначала файлы (им нужны inode), потом каталоги со списком имён.
    # Каталоги / и /bin ссылаются на inode, поэтому inode выделяем заранее,
    # а блоки данных пишем в порядке: файлы, затем каталоги.
    # add_file выделяет inode с 11, но 11 и 12 заняты каталогами.
    # Поэтому каталоги создаём первыми пустыми нельзя — см. ниже.
    file_inos = []
    # Резерв inode 11 lost+found и 12 /bin. Файлы с 13.
    fs.next_ino = 13
    stored = []
    for name, data in payloads:
        ino = fs.add_file(data)
        stored.append((name, ino, data))
        file_inos.append(ino)
    motd_ino = fs.add_file(motd)
    readme_ino = fs.add_file(readme)

    bin_entries = [(ino, n.encode(), FT_REG) for n, ino, _d in stored]
    fs.add_dir(12, INO_ROOT, bin_entries)
    fs.add_dir(11, INO_ROOT, [])
    root_entries = [
        (11, b"lost+found", FT_DIR),
        (12, b"bin", FT_DIR),
        (motd_ino, b"motd.txt", FT_REG),
        (readme_ino, b"readme.txt", FT_REG),
    ]
    fs.add_dir(INO_ROOT, INO_ROOT, root_entries)
    free_b, free_i = fs.finish(root_entries, 3)

    # Самопроверка: байты файлов читаются обратно, bitmap согласован.
    checks = [( "/motd.txt", motd), ("/readme.txt", readme)]
    for name, ino, data in stored:
        checks.append(("/bin/" + name, data))
    for path, data in checks:
        got = read_file_bytes(fs.img, lookup(fs.img, path))
        if got != data:
            raise SystemExit("roundtrip mismatch %s (%d vs %d)" % (path, len(got), len(data)))
    names = sorted(n for n, _i, _f in list_dir(fs.img, INO_ROOT))
    expect = ["bin", "lost+found", "motd.txt", "readme.txt"]
    if names != expect:
        raise SystemExit("root entries %s" % names)
    magic = struct.unpack_from("<H", fs.img, 1024 + 56)[0]
    if magic != 0xEF53:
        raise SystemExit("magic")
    print("  ext2 %d MiB free blocks %d free inodes %d file-max %d" % (
        FS_BYTES // (1024 * 1024), free_b, free_i, FILE_MAX))
    return fs.img


def ext2_at(image, offset):
    return image[offset : offset + FS_BYTES]


def assemble(bios_path, out_path):
    with open(bios_path, "rb") as f:
        bios = f.read()
    if len(bios) == 0 or len(bios) >= BOOT_RESERVE:
        raise SystemExit("bios image must be non-empty and < 16 MiB, got %d" % len(bios))
    print("ext2 root:")
    ext2 = build_fs_ordered()
    image = bytearray(BOOT_RESERVE + len(ext2))
    image[: len(bios)] = bios
    image[BOOT_RESERVE:] = ext2
    # Суперблок загрузчика не должен быть принят за ext2.
    if struct.unpack_from("<H", image, 1024 + 56)[0] == 0xEF53:
        print("  note: bootloader also has ext2 magic at +1024; kernel probes +16MiB first")
    got = read_file_bytes(ext2_at(image, BOOT_RESERVE), lookup(ext2_at(image, BOOT_RESERVE), "/bin/busybox"))
    busy = open(os.path.join(ROOT, "rootfs", "bin", "busybox"), "rb").read()
    if got != busy:
        raise SystemExit("assembled image lost busybox")
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, "wb") as f:
        f.write(image)
    digest = hashlib.sha256(image).hexdigest()
    print("image %s bytes %d sha256 %s" % (out_path, len(image), digest))
    return digest


def cat(image_path, offset, path):
    with open(image_path, "rb") as f:
        blob = f.read()
    fs = ext2_at(blob, offset)
    data = read_file_bytes(fs, lookup(fs, path))
    sys.stdout.buffer.write(data)


def main():
    if len(sys.argv) >= 2 and sys.argv[1] == "--cat":
        if len(sys.argv) != 5:
            raise SystemExit("usage: mk_ext2.py --cat IMAGE OFFSET PATH")
        cat(sys.argv[2], int(sys.argv[3], 0), sys.argv[4])
        return
    if len(sys.argv) != 3:
        raise SystemExit("usage: mk_ext2.py BIOS.img OUT.img")
    assemble(sys.argv[1], sys.argv[2])


if __name__ == "__main__":
    main()
