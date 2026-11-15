#!/usr/bin/env python3
"""Маленький ext2 (rev 0, блоки 1024) и подпись RUDRA-DISK в LBA 0.

Раскладка блоков:
  0 boot (байты 0..9 = RUDRA-DISK)
  1 superblock
  2 дескриптор группы
  3 bitmap блоков
  4 bitmap inode
  5-6 таблица inode (16 inode по 128 байт)
  7 каталог /
  8 /hello.txt
  9 /readme.txt

Образ больше тома: 1 МиБ, чтобы блочный слой мог писать LBA 200 мимо ext2.
"""
import os
import struct
import sys

BLOCK = 1024
BLOCKS = 64
IMAGE = 1024 * 1024
INODE_SIZE = 128
ROOT, HELLO, README = 2, 11, 12


def put(img, off, data):
    img[off : off + len(data)] = data


def set_bit(buf, bit):
    buf[bit // 8] |= 1 << (bit % 8)


def inode(mode, size, links, block):
    raw = bytearray(INODE_SIZE)
    struct.pack_into("<H", raw, 0, mode)
    struct.pack_into("<I", raw, 4, size)
    struct.pack_into("<H", raw, 26, links)
    struct.pack_into("<I", raw, 28, 2 if block else 0)  # 512-байтные секторы
    struct.pack_into("<I", raw, 40, block)
    return raw


def dirent(ino, name, rec_len):
    raw = struct.pack("<IHH", ino, rec_len, len(name)) + name
    if len(raw) > rec_len:
        raise SystemExit(f"dirent overflow {name!r}")
    return raw + b"\x00" * (rec_len - len(raw))


def build():
    img = bytearray(IMAGE)
    put(img, 0, b"RUDRA-DISK")

    sb = bytearray(1024)
    struct.pack_into("<I", sb, 0, 16)  # inodes
    struct.pack_into("<I", sb, 4, BLOCKS)
    struct.pack_into("<I", sb, 12, BLOCKS - 10)  # free blocks
    struct.pack_into("<I", sb, 16, 4)  # free inodes: 13..16
    struct.pack_into("<I", sb, 20, 1)  # first data block
    struct.pack_into("<I", sb, 24, 0)  # log block size -> 1024
    struct.pack_into("<I", sb, 32, BLOCKS)  # blocks per group
    struct.pack_into("<I", sb, 36, BLOCKS)
    struct.pack_into("<I", sb, 40, 16)  # inodes per group
    struct.pack_into("<H", sb, 56, 0xEF53)
    struct.pack_into("<H", sb, 58, 1)  # clean
    struct.pack_into("<I", sb, 76, 0)  # rev 0
    put(img, BLOCK, sb)

    gd = struct.pack("<IIIHHHH", 3, 4, 5, BLOCKS - 10, 4, 1, 0)
    put(img, 2 * BLOCK, gd)

    bb = bytearray(BLOCK)
    ib = bytearray(BLOCK)
    for b in range(10):
        set_bit(bb, b)
    for i in range(12):  # inodes 1..12
        set_bit(ib, i)
    put(img, 3 * BLOCK, bb)
    put(img, 4 * BLOCK, ib)

    table = bytearray(2 * BLOCK)
    def place(ino, raw):
        off = (ino - 1) * INODE_SIZE
        table[off : off + INODE_SIZE] = raw

    place(ROOT, inode(0x41ED, BLOCK, 2, 7))
    hello = b"hello from ext2\n"
    readme = b"rudra ext2\n"
    place(HELLO, inode(0x81A4, len(hello), 1, 8))
    place(README, inode(0x81A4, len(readme), 1, 9))
    put(img, 5 * BLOCK, table)
    put(img, 8 * BLOCK, hello)
    put(img, 9 * BLOCK, readme)

    names = [(ROOT, b"."), (ROOT, b".."), (HELLO, b"hello.txt"), (README, b"readme.txt")]
    off = 0
    raw_dir = bytearray()
    for i, (ino, name) in enumerate(names):
        min_len = (8 + len(name) + 3) & ~3
        rec = BLOCK - off if i == len(names) - 1 else min_len
        raw_dir += dirent(ino, name, rec)
        off += rec
    if len(raw_dir) != BLOCK:
        raise SystemExit(f"root dir is {len(raw_dir)} bytes")
    put(img, 7 * BLOCK, raw_dir)
    return img


def check(img):
    magic = struct.unpack_from("<H", img, BLOCK + 56)[0]
    if magic != 0xEF53:
        raise SystemExit("bad magic")
    if img[:10] != b"RUDRA-DISK":
        raise SystemExit("bad LBA0")
    # inode 11 лежит во втором блоке таблицы, смещение 256
    ino = 5 * BLOCK + INODE_SIZE * 10
    size, block = struct.unpack_from("<II", img, ino + 4)[0], struct.unpack_from("<I", img, ino + 40)[0]
    # size is at +4, but unpack_from of two I would be size and atime. Read separately.
    size = struct.unpack_from("<I", img, ino + 4)[0]
    block = struct.unpack_from("<I", img, ino + 40)[0]
    text = img[block * BLOCK : block * BLOCK + size]
    if text != b"hello from ext2\n":
        raise SystemExit(f"hello payload {text!r} block {block} size {size}")
    data = img[7 * BLOCK : 8 * BLOCK]
    found = []
    off = 0
    while off + 8 <= len(data):
        ino_n, rec, nlen = struct.unpack_from("<IHH", data, off)
        if rec < 8:
            break
        if ino_n and nlen:
            found.append(data[off + 8 : off + 8 + nlen])
        off += rec
    if b"hello.txt" not in found or b"readme.txt" not in found:
        raise SystemExit(f"root entries {found!r}")
    print(f"ext2 ok: LBA0 RUDRA-DISK, / -> {found}, hello={text!r}")


def main():
    out = sys.argv[1]
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    img = build()
    check(img)
    open(out, "wb").write(img)
    print(f"wrote {out} ({len(img)} bytes)")


if __name__ == "__main__":
    main()
