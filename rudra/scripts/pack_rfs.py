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


def main():
    src_dir, out_path = sys.argv[1], sys.argv[2]
    entries = []
    data = bytearray()

    for root, _dirs, files in os.walk(src_dir):
        for fname in sorted(files):
            path = os.path.join(root, fname)
            rel = os.path.relpath(path, src_dir).replace(os.sep, "/")
            fs_name = "/" + rel
            if len(fs_name) >= NAME_LEN:
                print(f"skip (name too long): {fs_name}", file=sys.stderr)
                continue
            payload = open(path, "rb").read()
            entries.append((fs_name, len(data), len(payload)))
            data += payload
            if len(entries) >= MAX_FILES:
                break
        if len(entries) >= MAX_FILES:
            break

    entries.sort(key=lambda e: e[0])
    # offset'ы считались до сортировки — пересобираем данные в порядке имён
    data = bytearray()
    packed = []
    for name, _off, size in entries:
        path = os.path.join(src_dir, name[1:].replace("/", os.sep))
        payload = open(path, "rb").read()
        packed.append((name, len(data), size))
        data += payload

    if DATA_OFF + len(data) > IMG_SIZE:
        print("rootfs does not fit into image", file=sys.stderr)
        sys.exit(1)

    img = bytearray(IMG_SIZE)
    struct.pack_into("<III", img, 0, MAGIC, len(packed), len(data))
    for i, (name, off, size) in enumerate(packed):
        base = TABLE_OFF + i * ENTRY_SIZE
        nb = name.encode()
        img[base : base + len(nb)] = nb
        struct.pack_into("<II", img, base + NAME_LEN, off, size)

    img[DATA_OFF : DATA_OFF + len(data)] = data
    open(out_path, "wb").write(img)
    print(f"rfs image: {len(packed)} files, {len(data)} bytes data -> {out_path}")


if __name__ == "__main__":
    main()
