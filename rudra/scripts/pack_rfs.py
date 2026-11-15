#!/usr/bin/env python3
"""Пакер rootfs -> ramdisk-образ rudra (RFS2).

Формат:
  [0]   magic "RFS2" (u32 LE)
  [4]   num_files (u32 LE)
  [8]   data_used (u32 LE, относительно DATA_OFF)
  [12..] 192 записей по 72 байта: name[64] (NUL-terminated), offset u32, size u32
  [16384..] данные файлов

rootfs каталог рекурсивно упаковывается в полные пути:
  rootfs/bin/busybox -> "/bin/busybox", rootfs/motd.txt -> "/motd.txt".
Каталоги — отдельные записи: старший бит offset (0x80000000), размер 0.
"""
import os
import struct
import sys

MAGIC = 0x32534652  # "RFS2"
MAX_FILES = 192
NAME_LEN = 64
ENTRY_SIZE = 72
TABLE_OFF = 12
DATA_OFF = 16 * 1024
IMG_SIZE = 8 * 1024 * 1024
DIR_BIT = 0x80000000


def main():
    src_dir, out_path = sys.argv[1], sys.argv[2]
    files = []
    dirs = set()

    for root, dirnames, filenames in os.walk(src_dir):
        rel_root = os.path.relpath(root, src_dir).replace(os.sep, "/")
        if rel_root != ".":
            dirs.add("/" + rel_root)
        for fname in sorted(filenames):
            path = os.path.join(root, fname)
            rel = os.path.relpath(path, src_dir).replace(os.sep, "/")
            fs_name = "/" + rel
            if len(fs_name) >= NAME_LEN:
                print(f"skip (name too long): {fs_name}", file=sys.stderr)
                continue
            files.append(fs_name)
            parent = fs_name
            while True:
                parent = parent.rsplit("/", 1)[0]
                if not parent:
                    break
                dirs.add(parent)
        if len(files) >= MAX_FILES:
            break

    files.sort()
    data = bytearray()
    packed = []
    for name in files:
        path = os.path.join(src_dir, name[1:].replace("/", os.sep))
        payload = open(path, "rb").read()
        packed.append((name, len(data), len(payload)))
        data += payload

    if DATA_OFF + len(data) > IMG_SIZE:
        print("rootfs does not fit into image", file=sys.stderr)
        sys.exit(1)

    dir_entries = sorted(d for d in dirs if 0 < len(d) < NAME_LEN)
    records = [(name, DIR_BIT, 0) for name in dir_entries]
    records.extend(packed)
    if len(records) > MAX_FILES:
        print("too many files and directories", file=sys.stderr)
        sys.exit(1)

    img = bytearray(IMG_SIZE)
    struct.pack_into("<III", img, 0, MAGIC, len(records), len(data))
    for i, (name, off, size) in enumerate(records):
        base = TABLE_OFF + i * ENTRY_SIZE
        nb = name.encode()
        img[base : base + len(nb)] = nb
        struct.pack_into("<II", img, base + NAME_LEN, off, size)

    img[DATA_OFF : DATA_OFF + len(data)] = data
    open(out_path, "wb").write(img)
    print(
        f"rfs image: {len(dir_entries)} dirs, {len(packed)} files, "
        f"{len(data)} bytes data -> {out_path}"
    )


if __name__ == "__main__":
    main()
