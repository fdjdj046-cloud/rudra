# Профили

Тег **2.0.0 — только Server**. Пункты с пометкой **D** и весь раздел 9 требований в `main` не входят. Их место — ветки `desktop-3.x` (линии 3.0, 3.1, …). Общие пункты без пометки S/D остаются на `main`: они нужны серверу, и десктоп потом возьмёт их оттуда, а не наоборот.

Ветка `desktop-3.x` не создаётся, пока на `main` нет базы, без которой десктоп не загрузится: SMP, VFS, динамический линкер, сеть. До этого момента десктопный код не начинается.

| Область | Server, путь к 2.0.0 (`main`) | Desktop (`desktop-3.x`) |
|---|---|---|
| Загрузка | ISO, TUI и автоустановка, cloud-образы, live, rescue, A/B-обновления, подпись | GUI-установщик, dual-boot, splash |
| Железо | virtio-blk/net/scsi, NVMe, AHCI, e1000/e1000e, r8169, Hyper-V, vmxnet3, ENA, gVNIC, USB xHCI для консоли и диска | Wi-Fi, Bluetooth, GPU с ускорением, звук, тачпад, suspend |
| Графика | framebuffer и virtio-gpu как консоль, не как рабочий стол | DRM/KMS, evdev, Wayland, Mesa |
| Сеть | IPv4/IPv6, сокеты, netlink, DHCP, DNS, nftables, мост, VLAN, veth, SSH | NetworkManager-подобный GUI, Wi-Fi |
| Userspace | PID1, пользователи, пакеты, nginx, PostgreSQL, Redis, OpenSSH, контейнеры | браузер, звук, экран блокировки, центр приложений |
| Не в этом профиле | Kubernetes control plane, live patching, HA | Wine, Steam, NVIDIA, NTFS как цель релиза |

Минимальный серверный образ, облачные образы и приёмочный набор (nginx, PostgreSQL, Redis, OpenSSH, контейнеры) — критерий 2.0.0. Wayland, браузер и suspend — критерий 3.x, не 2.0.0.
