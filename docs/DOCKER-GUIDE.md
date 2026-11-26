# Docker Guide

This guide covers running `rusty-conduit-switch` in a container with `docker run` and Docker
Compose: the published images, the config file and hot-reload, reaching upstream proxies,
secrets, logs, HTTPS MITM, resource limits, health checks, and hardening.

- Back to [README](../README.md) · [Basic User Guide](USER-GUIDE-BASIC.md) · [Advanced User
  Guide](USER-GUIDE-ADVANCED.md) · [Performance, Footprint & Sizing](PERFORMANCE-AND-SIZING.md)

The examples were tested with Docker Engine 29.9 and Docker Compose 5.7 on Docker Desktop
(Linux arm64). The file-ownership notes for Linux hosts were checked with files owned by
another UID.

---

## 1. Images

| | |
| :--- | :--- |
| **Image** | `ghcr.io/jpbaking/rusty-conduit-switch` |
| **Tags** | `X.Y.Z`, `X.Y`, `X`, and `latest` (the newest stable release). A pre-release gets only its full version tag. |
| **Platforms** | `linux/amd64`, `linux/arm64` |
| **Base** | Ubuntu 26.04 LTS with `ca-certificates` |
| **User** | `rusty-conduit-switch`, UID and GID `10001`, set as a numeric `USER 10001:10001` so orchestrators can verify it is not root (Kubernetes `runAsNonRoot`). Nothing in the image runs as root. |
| **Entrypoint** | `/usr/local/bin/rusty-conduit-switch`. Anything after the image name is passed to it as arguments. |
| **Ports** | `3128` (HTTP/HTTPS) and `1080` (SOCKS4/4a/5) |
| **Environment** | `RUSTY_CONDUIT_SWITCH_BIND=0.0.0.0`, so the listeners accept connections forwarded by Docker, and `MALLOC_ARENA_MAX=2`, which keeps memory low on hosts with many CPUs |

Pin a major tag such as `:1` so you get fixes and features within that major version, but not
breaking changes. To build the image yourself from a clone of the repository:

```sh
docker build -t rusty-conduit-switch .
```

---

## 2. Run with `docker run`

```sh
docker run -d --name rusty-conduit-switch --restart unless-stopped \
  -p 127.0.0.1:3128:3128 \
  -p 127.0.0.1:1080:1080 \
  -v "$PWD/conf:/etc/rusty-conduit-switch:ro" \
  ghcr.io/jpbaking/rusty-conduit-switch:1 \
  --config /etc/rusty-conduit-switch/config.toml --watch-config
```

- **Publish on `127.0.0.1`.** Inside the container the proxy listens on `0.0.0.0`, so the
  `SECURITY NOTICE` at startup is expected. What decides who can reach it is the host side of
  `-p`: `-p 3128:3128` without an address exposes the proxy to your network, and v1 has **no
  inbound authentication**.
- **Flags and environment variables** work as usual: put flags after the image name, or pass
  `-e RUSTY_CONDUIT_SWITCH_*` variables.
- **Memory:** the image sets `MALLOC_ARENA_MAX=2`, which keeps memory low on hosts with many
  CPUs. Leave it in place unless you measure otherwise; see [Performance, Footprint &
  Sizing](PERFORMANCE-AND-SIZING.md#memory-on-many-core-linux-malloc_arena_max).
- **Logs:** `docker logs -f rusty-conduit-switch`.
- **Stop:** `docker stop rusty-conduit-switch` sends `SIGTERM`, and active connections drain
  before exit.


### File ownership on Linux hosts

Mounted files keep their host owner, and the image never runs as root, so it cannot fix
ownership or modes at startup. This matters when you mount a CA key, a password or passphrase
file, a log directory, or a directory for `import-airswitch -o`:

| Host | Do this |
| :--- | :--- |
| **Linux (recommended)** | Run the container as your own UID: `--user "$(id -u):$(id -g)"` (Compose: `user: "1000:1000"`, with your numbers). Your files stay yours, at their usual modes, with no `sudo`. The process is still not root. A named volume at `/var/log/rusty-conduit-switch` belongs to UID `10001`, so write logs to a host directory you own instead. |
| **Linux, image user** | Keep UID `10001` and hand it the files: `sudo chown 10001 <file or directory>`, keeping secret files at mode `600`. |
| **Docker Desktop** (macOS, Windows) | Nothing: Docker Desktop maps file ownership to the container user. |

---

## 3. Checking a config and a route

Run the subcommands in a throwaway container with the same mount:

```sh
docker run --rm -v "$PWD/conf:/etc/rusty-conduit-switch:ro" \
  ghcr.io/jpbaking/rusty-conduit-switch:1 validate --config /etc/rusty-conduit-switch/config.toml
# config OK: /etc/rusty-conduit-switch/config.toml profiles=3 rules=1

docker run --rm -v "$PWD/conf:/etc/rusty-conduit-switch:ro" \
  ghcr.io/jpbaking/rusty-conduit-switch:1 test-route --config /etc/rusty-conduit-switch/config.toml www.example.com:443
# target=www.example.com:443 inbound=http table=[routing] rule=example-via-corp profile=corp chain=corp,direct upstream=http://corp-proxy:3128
```

`validate` checks settings, not the files they name: an unreadable CA key or `password_file`
still passes, and fails only when the proxy starts. To turn an AirSwitch backup into a config,
mount a writable directory:

```sh
docker run --rm -v "$PWD/conf:/work" ghcr.io/jpbaking/rusty-conduit-switch:1 \
  import-airswitch /work/OmegaOptions.bak -o /work/config.toml
```

On Linux hosts, the container's UID must be able to write the directory for `-o` to work ([File
ownership](#file-ownership-on-linux-hosts)); otherwise print to stdout and redirect on the
host: `... import-airswitch /work/OmegaOptions.bak > conf/config.toml`.

---

## 4. Configuration file and hot-reload

Mount the config **directory**, not the single file. Both reload triggers then work:

- **`--watch-config`** sees edits made on the host, including editors that save by writing a
  new file and renaming it over the old one.
- **`SIGHUP`:** `docker kill --signal HUP rusty-conduit-switch` (or `docker compose kill -s HUP
  rusty-conduit-switch`).

A successful reload logs `config reloaded generation=N ...`; a bad edit logs an `ERROR` and the
running config stays active.

With a single-file mount (`-v "$PWD/config.toml:/etc/rusty-conduit-switch/config.toml:ro"`), a
rename-on-save leaves the container pointing at a file that no longer exists: the edit is never
seen, and the path inside the container disappears.

---

## 5. Reaching upstream proxies from a container

Profile `host` values are resolved and dialed **from inside the container**:

| Upstream | `host` in the profile |
| :--- | :--- |
| A proxy on your LAN or the internet | Its address or name, as on the host |
| Another container on the same Compose network | Its service name, for example `corp-proxy` |
| A proxy on the Docker host itself, such as an `ssh -D` SOCKS port | `host.docker.internal`. On Linux, add `--add-host host.docker.internal:host-gateway` (Compose: `extra_hosts: ["host.docker.internal:host-gateway"]`) |

`127.0.0.1` in a profile means the container's own loopback, not the host's. On Docker Desktop,
`host.docker.internal` also reaches services bound to the host's `127.0.0.1`. On a Linux host,
it maps to the Docker bridge, so the host service must listen on an address the bridge can
reach.

---

## 6. Secrets: upstream passwords and the MITM CA

Keep upstream passwords out of the config file:

- **`password_env`:** pass the variable with `-e CORP_PROXY_PASS` (taken from your shell) or
  Compose `environment:`. Environment variables are visible to anyone who can run `docker
  inspect`.
- **`password_file`:** mount the file read-only, or use a Compose secret, and point the profile
  at it, for example `password_file = "/run/secrets/corp_pass"` ([section
  9.3](#93-routing-with-an-upstream-proxy-a-password-secret-and-hot-reload)).

For HTTPS MITM, create a CA as described in the [MITM CA Guide](MITM-CA-GUIDE.md), mount it
read-only, and set `--mitm-ca-cert` and `--mitm-ca-key` (or the `[mitm]` keys) to the paths
inside the container.

The container's UID must be able to read every secret file ([File
ownership](#file-ownership-on-linux-hosts)). An unreadable CA key stops the proxy at startup
with `FATAL MITM setup failed: failed to read MITM CA file ...: Permission denied`.

---

## 7. Logs

Diagnostics go to `stderr`, which `docker logs` shows. For HTTP access and SOCKS connection
records, choose one of these:

**On `stdout`.** At `--log-level DEBUG`, records are also written to `stdout`, so Docker's log
driver collects them. Diagnostics stay on `stderr`, so you can split the two:

```sh
docker logs rusty-conduit-switch 2>/dev/null   # access and SOCKS records only
```

**In files.** Mount a volume at the image's log directory and point the log flags at it:

```sh
docker run -d --name rusty-conduit-switch \
  -p 127.0.0.1:3128:3128 -p 127.0.0.1:1080:1080 \
  -v "$PWD/conf:/etc/rusty-conduit-switch:ro" \
  -v rusty-conduit-switch-logs:/var/log/rusty-conduit-switch \
  ghcr.io/jpbaking/rusty-conduit-switch:1 --config /etc/rusty-conduit-switch/config.toml \
  --http-access-log /var/log/rusty-conduit-switch/http.log \
  --socks-log /var/log/rusty-conduit-switch/socks.log

docker exec rusty-conduit-switch tail -f /var/log/rusty-conduit-switch/access.log
```

- The image's `/var/log/rusty-conduit-switch` belongs to the container user (UID `10001`), so a
  new named volume mounted there is writable as is. To keep the files in a host directory
  instead, mount it there (`-v "$PWD/logs:/var/log/rusty-conduit-switch"`) and make it writable
  by the container's UID ([File ownership](#file-ownership-on-linux-hosts)).
- Records reach the files as soon as the proxy has no more queued, so `tail -f` follows them
  live; `docker stop` flushes the rest at shutdown.
- Log settings need a restart; a hot-reload does not change them.

---

## 8. Resource limits, health checks, and hardening

| Limit | Inside the container | What to do |
| :--- | :--- | :--- |
| Open files (`ulimit -n`) | Usually high: `1048576` on Docker Desktop. The proxy raises its soft limit toward the hard limit at startup. | If startup logs `NOTICE: open-file limit is ...`, add `--ulimit nofile=65536`, or lower `--max-connections`. It needs `2 × max_connections + 64`. |
| Listen backlog (`somaxconn`) | The container has its own network namespace; the default is `4096` on Linux 5.4 and later. | On older kernels, add `--sysctl net.core.somaxconn=4096`. With `--network host`, the host's value applies and `--sysctl` is not allowed. |
| Memory | The image sets `MALLOC_ARENA_MAX=2`, so memory stays low on any CPU count. | Add `--memory` as a ceiling if you want one. |
| CPUs | One worker thread per CPU the container may use. | `--cpus=2` also reduces idle memory. |

**Health check.** The image has no `curl` or `nc`, but it has `bash`, which can open a TCP
connection to the listener. The check passes while the HTTP listener accepts connections:

```sh
--health-cmd 'bash -c "exec 3<>/dev/tcp/127.0.0.1/3128"' \
--health-interval 30s --health-timeout 3s --health-retries 3
```

**Hardening.** The proxy writes nothing except the log files you configure, and needs no Linux
capabilities. `--read-only --cap-drop ALL --security-opt no-new-privileges:true` were tested
with every example in this guide. Keep the published ports on `127.0.0.1`, or behind a
firewall, until inbound authentication exists.

---

## 9. Docker Compose

Save an example as `compose.yaml`, then:

```sh
docker compose up -d
docker compose logs -f
docker compose down
```

### 9.1 Minimal

```yaml
services:
  rusty-conduit-switch:
    image: ghcr.io/jpbaking/rusty-conduit-switch:1
    restart: unless-stopped
    command: ["--config", "/etc/rusty-conduit-switch/config.toml", "--watch-config"]
    ports:
      - "127.0.0.1:3128:3128"
      - "127.0.0.1:1080:1080"
    volumes:
      - ./conf:/etc/rusty-conduit-switch:ro
```

### 9.2 A proxy for other containers

Services on the same Compose network reach the proxy by its service name. This proxy publishes
no ports, so nothing outside the network can use it:

```yaml
services:
  proxy:
    image: ghcr.io/jpbaking/rusty-conduit-switch:1
    restart: unless-stopped
    command: ["--config", "/etc/rusty-conduit-switch/config.toml", "--watch-config"]
    volumes:
      - ./conf:/etc/rusty-conduit-switch:ro

  app:
    image: curlimages/curl:latest
    command: ["-sS", "-o", "/dev/null", "-w", "%{http_code}\n", "https://example.com/"]
    environment:
      HTTP_PROXY: http://proxy:3128
      HTTPS_PROXY: http://proxy:3128
      NO_PROXY: localhost,127.0.0.1
    depends_on:
      - proxy
```

Tools differ in which names they read: `curl`, for example, ignores `HTTP_PROXY` and reads only
the lowercase `http_proxy` for `http://` URLs. Set both forms if a client ignores the proxy.
For SOCKS, use `ALL_PROXY: socks5h://proxy:1080`.

### 9.3 Routing with an upstream proxy, a password secret, and hot-reload

This example routes `*.example.com` through an upstream HTTP proxy, with `direct` as the
fallback. The `corp-proxy` service stands in for your real upstream: it runs `rusty-conduit`,
so the example works on its own. Replace it, and the profile's `host`, with your proxy.

The layout next to `compose.yaml`:

```text
conf/config.toml
secrets/corp_pass     # Linux hosts: see File ownership in section 2
```

`conf/config.toml`:

```toml
[profiles.corp]
type = "http"
host = "corp-proxy"
port = 3128
username = "alice"
password_file = "/run/secrets/corp_pass"

[routing]
default = "direct"

[[routing.rules]]
name = "example-via-corp"
host_wildcard = ["*.example.com"]
target = ["corp", "direct"]
```

`compose.yaml`:

```yaml
services:
  rusty-conduit-switch:
    image: ghcr.io/jpbaking/rusty-conduit-switch:1
    restart: unless-stopped
    command: ["--config", "/etc/rusty-conduit-switch/config.toml", "--watch-config"]
    ports:
      - "127.0.0.1:3128:3128"
      - "127.0.0.1:1080:1080"
    volumes:
      - ./conf:/etc/rusty-conduit-switch:ro
    secrets:
      - corp_pass
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    healthcheck:
      test: ["CMD", "bash", "-c", "exec 3<>/dev/tcp/127.0.0.1/3128"]
      interval: 30s
      timeout: 3s
      retries: 3
      start_period: 5s

  corp-proxy:
    image: ghcr.io/jpbaking/rusty-conduit:1
    command: ["--log-level", "DEBUG"]

secrets:
  corp_pass:
    file: ./secrets/corp_pass
```

Check it, then follow a request through:

```sh
docker compose run --rm --no-deps rusty-conduit-switch validate --config /etc/rusty-conduit-switch/config.toml
docker compose up -d
curl -x http://127.0.0.1:3128 https://www.example.com/
docker compose logs corp-proxy    # the CONNECT arrived through the upstream
```

Edit `conf/config.toml` on the host and save: the change applies without a restart.

---

## 10. Troubleshooting

| Symptom | Cause | Fix |
| :--- | :--- | :--- |
| Edits to the config are not picked up | The single file is mounted, not its directory | Mount the directory ([section 4](#4-configuration-file-and-hot-reload)) |
| A profile pointing at `127.0.0.1` fails | Inside the container, `127.0.0.1` is the container itself | Use `host.docker.internal` or the upstream's real address ([section 5](#5-reaching-upstream-proxies-from-a-container)) |
| `FATAL MITM setup failed: failed to read MITM CA file ...: Permission denied` | The key file is not readable by the container's UID | Run as your own UID, or `sudo chown 10001` the key ([File ownership](#file-ownership-on-linux-hosts)) |
| `Permission denied` opening a log file at startup | The container's UID cannot create files in the log directory | Use a named volume, or a host directory the container's UID can write ([File ownership](#file-ownership-on-linux-hosts)) |
| Clients on other machines cannot connect | The ports are published on `127.0.0.1` | Publish on a LAN address or `0.0.0.0` only behind a firewall: v1 has no inbound authentication |
| `SECURITY NOTICE: binding to non-loopback address 0.0.0.0` at startup | Expected: the proxy listens on all interfaces inside the container | Control exposure with the host side of `-p` |
| Memory is much higher than the sizing guide says | `MALLOC_ARENA_MAX` was overridden or unset, so glibc allocates a memory arena per worker thread | Keep the image default, `MALLOC_ARENA_MAX=2` ([section 8](#8-resource-limits-health-checks-and-hardening)) |
