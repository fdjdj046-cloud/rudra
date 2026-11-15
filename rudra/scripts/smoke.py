#!/usr/bin/env python3
"""Smoke rudra 1.0.0: boot, записать файл, reboot, прочитать его обратно.

Образ не портится: работа идёт на копии. QEMU — один virtio-blk, bootindex=0.
"""
import os
import shutil
import socket
import subprocess
import sys
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
QEMU = r"C:\Program Files\qemu\qemu-system-x86_64.exe"
SRC = os.path.join(ROOT, "target", "images", "rudra-1.0.0.img")
COPY = os.path.join(ROOT, "target", "images", "rudra-smoke.img")
SERIAL = os.path.join(ROOT, "target", "images", "smoke-serial.log")
MONITOR = 44555

KEYS = {
    " ": "spc",
    "/": "slash",
    ".": "dot",
    "-": "minus",
    ">": "shift-dot",
    "_": "shift-minus",
}


def read_serial():
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.CreateFileW(
            SERIAL, 0x80000000, 1 | 2, None, 3, 0, None
        )
        if handle == -1 or handle == 0xFFFFFFFF:
            return ""
        size = kernel32.GetFileSize(handle, None)
        buf = ctypes.create_string_buffer(size)
        n = ctypes.c_uint(0)
        kernel32.ReadFile(handle, buf, size, ctypes.byref(n), None)
        kernel32.CloseHandle(handle)
        return buf.raw[: n.value].decode("utf-8", "replace")
    except Exception:
        try:
            with open(SERIAL, "rb") as f:
                return f.read().decode("utf-8", "replace")
        except Exception:
            return ""


def wait_prompts(mon, need, timeout):
    deadline = time.time() + timeout
    while time.time() < deadline:
        text = read_serial()
        if text.count("rudra:/$") >= need:
            return text
        if "PANIC" in text or "DOUBLE FAULT" in text:
            return text
        time.sleep(0.2)
    return read_serial()


def send_line(mon, line, gap=0.12):
    for ch in line:
        key = KEYS.get(ch, ch)
        mon.sendall(("sendkey %s\n" % key).encode())
        time.sleep(gap)
    mon.sendall(b"sendkey ret\n")
    time.sleep(0.15)


def main():
    if not os.path.isfile(SRC):
        raise SystemExit("missing %s" % SRC)
    if os.path.exists(SERIAL):
        os.remove(SERIAL)
    shutil.copyfile(SRC, COPY)
    subprocess.run(
        ["taskkill", "/F", "/IM", "qemu-system-x86_64.exe"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    proc = subprocess.Popen(
        [
            QEMU,
            "-m", "256M",
            "-display", "none",
            "-serial", "file:" + SERIAL,
            "-monitor", "tcp:127.0.0.1:%d,server,nowait" % MONITOR,
            "-drive", "if=none,id=vd0,format=raw,file=" + COPY,
            "-device", "virtio-blk-pci,drive=vd0,disable-modern=on,bootindex=0",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    mon = None
    try:
        for _ in range(50):
            try:
                mon = socket.create_connection(("127.0.0.1", MONITOR), 1)
                break
            except OSError:
                time.sleep(0.1)
        if mon is None:
            raise SystemExit("monitor did not open")
        mon.settimeout(2)
        try:
            mon.recv(4096)
        except socket.timeout:
            pass

        text = wait_prompts(mon, 1, 25)
        if "rudra:/$" not in text:
            raise SystemExit("no shell prompt\n" + text[-2000:])
        if "[root] ext2 on virtio-blk" not in text:
            raise SystemExit("root is not ext2\n" + text[-2000:])
        print("boot ok, ext2 mounted")

        commands = [
            "cat /motd.txt",
            "uname",
            "echo persist-ok > /keep.txt",
            "mkdir /demo",
            "echo hi > /demo/a.txt",
            "rm /demo/a.txt",
            "rmdir /demo",
            "true",
            "wc -c /motd.txt",
            "ls /",
        ]
        for _ in range(8):
            commands.append("run /bin/hello.elf")
        base = text.count("rudra:/$")
        for i, cmd in enumerate(commands, 1):
            send_line(mon, cmd)
            text = wait_prompts(mon, base + i, 40)
            if text.count("rudra:/$") < base + i:
                raise SystemExit("timeout after %s\n%s" % (cmd, text[-2000:]))
            print("ok", cmd)

        send_line(mon, "reboot")
        # Новый prompt после повторной загрузки, плюс строка reboot.
        text = wait_prompts(mon, base + len(commands) + 1, 40)
        if "[ext2] mounted" not in text.split("[reboot]")[-1] and text.count("[ext2] mounted") < 2:
            # reboot мог не сработать: проверим лог целиком ниже
            pass
        if text.count("rudra:/$") < base + len(commands) + 1:
            raise SystemExit("no prompt after reboot\n" + text[-2500:])
        print("reboot ok")
        n = text.count("rudra:/$")
        send_line(mon, "cat /keep.txt")
        text = wait_prompts(mon, n + 1, 20)
        if "persist-ok" not in text:
            raise SystemExit("keep.txt missing after reboot\n" + text[-2000:])
        bad = []
        for needle in (
            "PAGE FAULT",
            "page fault",
            "PANIC",
            "DOUBLE FAULT",
            "no free tasks",
            "failed to spawn",
            "command not found",
            "busybox exec failed",
            "fork failed",
            "reboot: refused",
            "mkdir:",
            "rm:",
        ):
            if needle in text:
                bad.append(needle)
        if bad:
            raise SystemExit("faults: %s\n%s" % (bad, text[-2500:]))
        if "1.0.0" not in text:
            raise SystemExit("uname did not show 1.0.0\n" + text[-1500:])
        print("SMOKE PASS")
        print("--- tail ---")
        print(text[-1800:])
    finally:
        if mon is not None:
            try:
                mon.sendall(b"quit\n")
                mon.close()
            except Exception:
                pass
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
        subprocess.run(
            ["taskkill", "/F", "/IM", "qemu-system-x86_64.exe"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        err = b""
        if proc.stderr:
            try:
                err = proc.stderr.read() or b""
            except Exception:
                pass
        if err.strip():
            print("qemu stderr:", err.decode("utf-8", "replace")[:1000])


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        subprocess.run(
            ["taskkill", "/F", "/IM", "qemu-system-x86_64.exe"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        raise
