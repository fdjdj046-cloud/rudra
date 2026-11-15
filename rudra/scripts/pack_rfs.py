#!/usr/bin/env python3
"""Пакер rootfs -> ramdisk-образ rudra (RFS1).

Формат:
  [0]   magic "RFS1" (u32 LE)
  [4]   num_files (u32 LE)
  [8]   data_used (u32 LE, относительно DATA_OFF)
  [12..] 64 записей по 32 байта: name[24] (NUL-terminated), offset u32, size u32
  [4096..] данные файлов

Плоское пространство имён: файл = "/имя" (без подкаталогов, '/' ведущий).
"""
import os
import struct
import sys

MAGIC = 0x31534652  # "RFS1"
MAX_FILES = 64
NAME_LEN = 24
ENTRY_SIZE = 32
TABLE_OFF = 12
DATA_OFF = 4096
IMG_SIZE = 256 * 1024


def main():
    src_dir, out_path = sys.argv[1], sys.argv[2]
    entries = []
    data = bytearray()

    for name in sorted(os.listdir(src_dir)):
        path = os.path.join(src_dir, name)
        if not os.path.isfile(path):
            continue
        fs_name = "/" + name
        if len(fs_name) >= NAME_LEN:
            print(f"skip (name too long): {fs_name}", file=sys.stderr)
            continue
        payload = open(path, "rb").read()
        entries.append((fs_name, len(data), len(payload)))
        data += payload
        if len(entries) >= MAX_FILES:
            break

    if DATA_OFF + len(data) > IMG_SIZE:
        print("rootfs does not fit into image", file=sys.stderr)
        sys.exit(1)

    img = bytearray(IMG_SIZE)
    struct.pack_into("<III", img, 0, MAGIC, len(entries), len(data))
    for i, (name, off, size) in enumerate(entries):
        base = TABLE_OFF + i * ENTRY_SIZE
        nb = name.encode()
        img[base : base + len(nb)] = nb
        struct.pack_into("<II", img, base + NAME_LEN, off, size)

    img[DATA_OFF : DATA_OFF + len(data)] = data
    open(out_path, "wb").write(img)
    print(f"rfs image: {len(entries)} files, {len(data)} bytes data -> {out_path}")


if __name__ == "__main__":
    main()
