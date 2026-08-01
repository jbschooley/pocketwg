# pocketwg

**A tiny, self-hosted WireGuard® tunnel manager with a web UI — for headless and embedded Linux.**

Think of the WireGuard mobile app (import a config, flip tunnels on/off, watch the handshake),
but as a single static binary you run on a router, SBC, or server. No Docker, no runtime,
no dependencies — it drives the in-kernel WireGuard module via `wg` + `ip`.

> Small-footprint by design — runs anywhere Linux + WireGuard does.

## Features

- **Import `.conf`** (upload or paste) — manage multiple client tunnels.
- **Enable/disable** each tunnel with a toggle; **live status**: up/down, endpoint, last handshake, rx/tx.
- **Generate keypairs** (Curve25519, in-process — no shell-out).
- **Own login** (independent username/password, set on first run; bcrypt-hashed).
- **Single static binary** (`CGO_ENABLED=0`) — runs on glibc *or* musl; **multi-arch** (arm64, amd64, arm, mipsle, …).
- **Local control socket** for an on-device touch UI (embedded targets).
- **Tiny footprint** — a few MB of binary, a few MB of RAM.

## Quick start

```sh
# build (needs Docker) — or use a release binary
./build.sh arm64 amd64            # -> dist/pocketwg-<arch>

# run (needs root / CAP_NET_ADMIN to manage interfaces)
sudo ./dist/pocketwg-amd64        # defaults: http :8088, state /var/lib/pocketwg, wg/ip from PATH
```

Open `http://<host>:8088`, set an admin login on first run, then import a WireGuard config and toggle it on.

Build without Docker: `CGO_ENABLED=0 go build -o pocketwg .`

## Requirements

- Linux with the **WireGuard kernel module** (`modprobe wireguard`, or built-in) — or a custom module (see below).
- **`wg`** (wireguard-tools) and **`ip`** (iproute2) in `PATH`.
- **root** or `CAP_NET_ADMIN` (creates//manages network interfaces).

## Configuration (env)

| Var | Default | Meaning |
|---|---|---|
| `PWG_HTTP` | `:8088` | web UI listen address |
| `PWG_DATA` | `/var/lib/pocketwg` | state dir (`pocketwg.json`) |
| `PWG_WG` | `wg` | path to the `wg` binary |
| `PWG_IP` | `ip` | path to the `ip` binary |
| `PWG_MODLOAD` | `modprobe wireguard` | command (via `sh -c`) to ensure the kernel module |
| `PWG_SOCK` | `<data>/pocketwg.sock` | local unix socket for the touch UI |

## Run as a service (systemd)

See [`contrib/pocketwg.service`](contrib/pocketwg.service):

```sh
sudo cp dist/pocketwg-amd64 /usr/local/bin/pocketwg
sudo cp contrib/pocketwg.service /etc/systemd/system/
sudo systemctl enable --now pocketwg
```

## Embedded / OpenWrt / custom kernels

`pocketwg` is arch-agnostic and drives standard `wg`/`ip`, so it drops onto routers and SBCs by
setting `PWG_WG`/`PWG_IP` and a service file. For devices that don't ship WireGuard in-kernel, build a
matching kernel module and point `PWG_MODLOAD` at your module-load command (an `insmod` chain, etc.).

## Roadmap

- **wg-quick parity**: full-tunnel routing (`AllowedIPs = 0.0.0.0/0` via policy routing + fwmark) and DNS handling.
- **On-device touch UI** (LVGL) for embedded screens, via the local control socket.
- Optional **OpenWrt uci/netifd** backend mode.
- **TLS** for LAN/remote admin (currently plain HTTP — bind localhost or reverse-proxy meanwhile).

## Security

- The web UI has its own login (bcrypt). Still, it manages your VPN — bind it to a trusted interface
  (`PWG_HTTP=127.0.0.1:8088` + reverse proxy) or wait for built-in TLS before exposing it.
- Runs as root by design (network admin). The local control socket is `0600`, local-only.

## License

**AGPL-3.0** — see [LICENSE](LICENSE). If you run a modified version as a network service, the AGPL
requires you to offer its source to users of that service. Source: https://github.com/jbschooley/pocketwg

---

*WireGuard is a registered trademark of Jason A. Donenfeld. This project is not affiliated with,
sponsored by, or endorsed by WireGuard or Jason A. Donenfeld.*
