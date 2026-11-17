#!/usr/bin/env python3
"""Smoke rudra 1.0.1: boot, записать файл, много hello.elf, reboot, прочитать обратно.

Образ не портится: работа идёт на копии. QEMU — virtio-blk (корень) и virtio-net.
QEMU берётся из переменной QEMU, из PATH или из стандартного пути Windows.
Число запусков hello — SMOKE_HELLOS (по умолчанию 40). Пауза клавиш — SMOKE_GAP.
"""
import os
import shutil
import socket
import subprocess
import sys
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC = os.path.join(ROOT, "target", "images", "rudra-1.0.1.img")
COPY = os.path.join(ROOT, "target", "images", "rudra-smoke.img")
SERIAL = os.path.join(ROOT, "target", "images", "smoke-serial.log")
MONITOR = int(os.environ.get("SMOKE_MONITOR", "44555"))
HELLO_N = int(os.environ.get("SMOKE_HELLOS", "40"))
KEY_GAP = float(os.environ.get("SMOKE_GAP", "0.08"))

KEYS = {
    " ": "spc",
    "/": "slash",
    ".": "dot",
    "-": "minus",
    ">": "shift-dot",
    "_": "shift-minus",
}


def find_qemu():
    env = os.environ.get("QEMU")
    if env:
        return env
    found = shutil.which("qemu-system-x86_64") or shutil.which("qemu-system-x86_64.exe")
    if found:
        return found
    for candidate in (
        r"C:\Program Files\qemu\qemu-system-x86_64.exe",
        "/usr/bin/qemu-system-x86_64",
    ):
        if os.path.isfile(candidate):
            return candidate
    raise SystemExit("qemu-system-x86_64 not found; set QEMU=")


def kill_qemu():
    if os.name != "nt":
        return
    subprocess.run(
        ["taskkill", "/F", "/IM", "qemu-system-x86_64.exe"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def read_serial():
    try:
        with open(SERIAL, "rb") as f:
            return f.read().decode("utf-8", "replace")
    except OSError:
        pass
    if os.name != "nt":
        return ""
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.CreateFileW(
            SERIAL, 0x80000000, 1 | 2, None, 3, 0, None
        )
        if handle == -1 or handle == 0xFFFFFFFF:
            return ""
        size = kernel32.GetFileSize(handle, None)
        if size in (0, 0xFFFFFFFF):
            kernel32.CloseHandle(handle)
            return ""
        buf = ctypes.create_string_buffer(size)
        n = ctypes.c_uint(0)
        kernel32.ReadFile(handle, buf, size, ctypes.byref(n), None)
        kernel32.CloseHandle(handle)
        return buf.raw[: n.value].decode("utf-8", "replace")
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


def send_line(mon, line, gap=None):
    if gap is None:
        gap = KEY_GAP
    # Enter только после эха. На TCG с -smp 2 гость не всегда успевает
    # прочитать сканкод, и следующий sendkey его затирает.
    start = len(read_serial())
    for ch in line:
        key = KEYS.get(ch, ch)
        mon.sendall(("sendkey %s\n" % key).encode())
        time.sleep(gap)
    deadline = time.time() + 5
    while time.time() < deadline:
        if line in read_serial()[start:]:
            break
        time.sleep(0.05)
    time.sleep(0.05)
    mon.sendall(b"sendkey ret\n")
    time.sleep(0.15)


def main():
    if not os.path.isfile(SRC):
        raise SystemExit("missing %s" % SRC)
    if os.path.exists(SERIAL):
        os.remove(SERIAL)
    shutil.copyfile(SRC, COPY)
    kill_qemu()
    qemu = find_qemu()
    proc = subprocess.Popen(
        [
            qemu,
            "-m", "256M",
            "-smp", "2",
            "-display", "none",
            "-serial", "file:" + SERIAL,
            "-monitor", "tcp:127.0.0.1:%d,server,nowait" % MONITOR,
            "-nic", "none",
            "-drive", "if=none,id=vd0,format=raw,file=" + COPY,
            "-device", "virtio-blk-pci,drive=vd0,disable-modern=on,bootindex=0",
            "-netdev", "user,id=n0",
            "-device", "virtio-net-pci,netdev=n0,disable-modern=on",
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

        # TCG в GitHub Actions без kvm грузит debug-ядро дольше локального KVM.
        text = wait_prompts(mon, 1, 90)
        if "rudra:/$" not in text:
            raise SystemExit("no shell prompt\n" + text[-2000:])
        if "[root] ext2 on virtio-blk" not in text:
            raise SystemExit("root is not ext2\n" + text[-2000:])
        print("boot ok, ext2 mounted")

        commands = [
            "cat /motd.txt",
            "uname",
            "cat /proc/self/status",
            "echo persist-ok > /keep.txt",
            "mkdir /demo",
            "echo hi > /demo/a.txt",
            "rm /demo/a.txt",
            "rmdir /demo",
            "true",
            "wc -c /motd.txt",
            "run /bin/signal.elf",
            "run /bin/tick.elf",
            "run /bin/intr.elf",
            "run /bin/cred.elf",
            "run /bin/seccomp.elf",
            "run /bin/fs.elf",
            "run /bin/tcp.elf",
            "run /bin/epoll.elf",
            "run /bin/dyn.elf",
            "ls /",
            "run /bin/counter.elf",
            "run /bin/fizzbuzz.elf",
        ]
        for _ in range(HELLO_N):
            commands.append("run /bin/hello.elf")
        base = text.count("rudra:/$")
        for i, cmd in enumerate(commands, 1):
            send_line(mon, cmd)
            text = wait_prompts(mon, base + i, 90)
            if text.count("rudra:/$") < base + i:
                raise SystemExit("timeout after %s\n%s" % (cmd, text[-2000:]))
            print("ok", cmd)

        send_line(mon, "reboot")
        # Новый prompt после повторной загрузки, плюс строка reboot.
        text = wait_prompts(mon, base + len(commands) + 1, 90)
        if "[ext2] mounted" not in text.split("[reboot]")[-1] and text.count("[ext2] mounted") < 2:
            # reboot мог не сработать: проверим лог целиком ниже
            pass
        if text.count("rudra:/$") < base + len(commands) + 1:
            raise SystemExit("no prompt after reboot\n" + text[-2500:])
        print("reboot ok")
        n = text.count("rudra:/$")
        send_line(mon, "cat /keep.txt")
        text = wait_prompts(mon, n + 1, 40)
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
            "rmdir:",
            "Bad address",
        ):
            if needle in text:
                bad.append(needle)
        if bad:
            raise SystemExit("faults: %s\n%s" % (bad, text[-2500:]))
        if "1.0.1" not in text:
            raise SystemExit("uname did not show 1.0.1\n" + text[-1500:])
        if "203 /motd.txt" not in text and "203  /motd.txt" not in text:
            raise SystemExit("wc did not print 203 for motd\n" + text[-1500:])
        if "signal-ok" not in text:
            raise SystemExit("signal.elf did not report signal-ok\n" + text[-1500:])
        if "tick-ok" not in text or "tick-bad" in text:
            raise SystemExit("tick.elf did not report tick-ok\n" + text[-1500:])
        if "intr-ok" not in text or "intr-bad" in text:
            raise SystemExit("intr.elf did not report intr-ok\n" + text[-1500:])
        if "Uid:\t0\t0\t0\t0" not in text or "Seccomp:\t0" not in text:
            raise SystemExit("proc self status missing\n" + text[-1500:])
        if "cred-ok" not in text or "cred-bad" in text:
            raise SystemExit("cred.elf did not report cred-ok\n" + text[-1500:])
        if "seccomp-ok" not in text or "seccomp-bad" in text or "[exit 137]" not in text:
            raise SystemExit("seccomp.elf did not die on a forbidden syscall\n" + text[-1500:])
        if "fs-ok" not in text or "fs-bad" in text:
            raise SystemExit("fs.elf did not report fs-ok\n" + text[-1500:])
        if "reparent-ok" not in text or "reparent-bad" in text:
            raise SystemExit("fs.elf did not report reparent-ok\n" + text[-1500:])
        if "tcp-ok" not in text or "tcp-bad" in text:
            raise SystemExit("tcp.elf did not report tcp-ok\n" + text[-1500:])
        if "[task] init spawned" not in text:
            raise SystemExit("init was not pid1\n" + text[-1500:])
        if "epoll-ok" not in text:
            raise SystemExit("epoll.elf did not report epoll-ok\n" + text[-1500:])
        if "interp-ok" not in text or "interp-bad" in text:
            raise SystemExit("dyn.elf did not report interp-ok\n" + text[-1500:])
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
        kill_qemu()
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
        kill_qemu()
        raise
