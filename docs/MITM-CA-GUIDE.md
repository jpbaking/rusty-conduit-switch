# MITM CA Guide

rusty-conduit-switch can decrypt and log HTTPS traffic that passes through its HTTP proxy
port, whichever upstream profile the routing rules pick for it. To do that, it needs a
certificate authority (CA) that your clients trust.
**rusty-conduit-switch never generates a CA for you.** You create one, keep its private key safe,
and choose which machines and browsers trust it.

This guide covers:

1. [Security warnings](#1-security-warnings): read these first.
2. [Generating a private CA](#2-generating-a-private-ca-with-openssl) with `openssl`, in PEM
   and PKCS#12 form.
3. [Starting rusty-conduit-switch with the CA](#3-starting-rusty-conduit-switch-with-the-ca).
4. [Trusting the CA](#4-trusting-the-ca) on Linux, macOS, Windows, Firefox, and common CLI tools.
5. [Removing the CA](#5-removing-the-ca-again) when you are done.

---

## 1. Security warnings

> **Anyone who has the CA private key can impersonate any HTTPS website to every device that
> trusts the CA.** Treat it like a master password.

- **Use a dedicated CA for rusty-conduit-switch.** Never reuse a CA that signs anything else, and never
  use a public or corporate CA.
- **Keep the key on the machine that runs the proxy.** Make it readable only by the account
  that runs rusty-conduit-switch (`chmod 600`, or a restrictive ACL on Windows). Never commit it to Git,
  copy it into container images, or paste it into chat or tickets.
- **Encrypt the key at rest.** Use an encrypted PKCS#8 key or a PKCS#12 bundle. Pass the
  passphrase through `RUSTY_CONDUIT_SWITCH_MITM_CA_PASSPHRASE` or `--mitm-ca-passphrase-file`.
  `--mitm-ca-passphrase` on the command line shows up in process listings and shell history,
  and rusty-conduit-switch prints a notice when you use it.
- **Install only the CA *certificate* (`ca.pem` / `ca.cer`) on clients**, never the key or the
  `.p12`.
- **Trust the CA only where you need interception**, and remove it when you no longer need it
  (see [section 5](#5-removing-the-ca-again)). Short CA lifetimes (for example 1–2 years) limit
  the damage if the key leaks.
- **Inspect only traffic you are authorized to inspect.** Decrypted logs can contain
  credentials, session tokens, and personal data. Protect `--http-access-log` files accordingly.
- **Some applications pin certificates** (banking apps, OS update services, and some
  messengers). They refuse intercepted connections. v1 cannot bypass MITM for specific
  domains; for those clients, use an instance without MITM, or SOCKS (unless you enable
  `--socks-block-web`).
- **v1 has no proxy authentication.** Keep `--bind` on loopback (the default), or restrict
  access with a firewall.

---

## 2. Generating a private CA with `openssl`

Any OpenSSL 3.x works. Windows users can get it from Git for Windows (Git Bash) or
`winget install ShiningLight.OpenSSL.Light`. Run these commands in a private directory:

```sh
mkdir -p ~/rusty-conduit-switch-ca && cd ~/rusty-conduit-switch-ca
umask 077          # new files readable by you only (Unix)
```

### 2.1 PEM certificate + key (recommended: ECDSA P-256)

```sh
openssl req -x509 -new \
  -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -noenc \
  -keyout ca.key -out ca.pem -days 825 \
  -subj "/CN=Rusty Conduit Switch Local CA/O=Homelab" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash"
```

This creates:

- `ca.pem`: the CA certificate. This is the file clients trust.
- `ca.key`: the unencrypted private key in PKCS#8 form. It stays secret.

`pathlen:0` stops the CA from creating intermediate CAs. rusty-conduit-switch only ever signs leaf
certificates directly with it.

If you need RSA instead, use `-newkey rsa:3072` and leave out `-pkeyopt`. rusty-conduit-switch
accepts these PEM key types:

- PKCS#8 (`PRIVATE KEY`)
- PKCS#1 RSA (`RSA PRIVATE KEY`)
- SEC1 EC (`EC PRIVATE KEY`)
- encrypted PKCS#8 (`ENCRYPTED PRIVATE KEY`)

Whatever the CA's key type, the leaf certificates rusty-conduit-switch generates always use ECDSA
P-256.

Check the result:

```sh
openssl x509 -in ca.pem -noout -subject -dates -ext basicConstraints,keyUsage
```

### 2.2 Encrypting the PEM key (optional, recommended)

```sh
printf '%s\n' 'choose-a-long-passphrase' > ca.pass     # or create it with an editor
openssl pkcs8 -topk8 -v2 aes-256-cbc -in ca.key -out ca.enc.key -passout file:ca.pass
rm ca.key   # keep only the encrypted key
```

rusty-conduit-switch reads encrypted PKCS#8 (`ENCRYPTED PRIVATE KEY`) keys. It **rejects** legacy
OpenSSL keys with `Proc-Type: 4,ENCRYPTED` headers, which `openssl ec -aes256` or
`openssl rsa -aes256` produce. Convert those with the `openssl pkcs8 -topk8 -v2 aes-256-cbc`
command above.

### 2.3 PKCS#12 bundle (`.p12` / `.pfx`)

Bundle the certificate and key into one passphrase-protected file:

```sh
openssl pkcs12 -export \
  -inkey ca.key -in ca.pem \
  -name "Rusty Conduit Switch Local CA" \
  -out ca.p12 -passout file:ca.pass
```

This needs the unencrypted `ca.key`. If you already encrypted it, use
`-inkey ca.enc.key -passin file:ca.pass`, and point `-passout` at a **different** file, for
example a copy made with `cp ca.pass p12.pass`. If both options name the same file, OpenSSL
reads the input passphrase from its first line and the output passphrase from its second line.

OpenSSL 3 writes PBES2/AES-256 bundles by default, and rusty-conduit-switch reads them. Older
bundles, such as those written with `-legacy` or exported by Windows or macOS tools, are
supported too. For a bundle without a passphrase, leave out every passphrase option; an empty
passphrase is used.

If you are given a `.pfx` exported from Windows, use it directly with `--mitm-ca-p12`.
rusty-conduit-switch uses the certificate that matches the bundled private key as the signing CA.

---

## 3. Starting rusty-conduit-switch with the CA

```sh
# PEM, unencrypted key
rusty-conduit-switch --mitm-ca-cert ca.pem --mitm-ca-key ca.key

# PEM, encrypted key
rusty-conduit-switch --mitm-ca-cert ca.pem --mitm-ca-key ca.enc.key --mitm-ca-passphrase-file ca.pass

# PKCS#12, passphrase from a file or from the environment
rusty-conduit-switch --mitm-ca-p12 ca.p12 --mitm-ca-passphrase-file ca.pass
RUSTY_CONDUIT_SWITCH_MITM_CA_PASSPHRASE='choose-a-long-passphrase' rusty-conduit-switch --mitm-ca-p12 ca.p12
```

Or set the CA in the TOML config file:

```toml
[mitm]
ca_p12 = "/etc/rusty-conduit-switch/ca.p12"
ca_passphrase_file = "/etc/rusty-conduit-switch/ca.pass"
cert_ttl = "1h"
cert_cache_max_entries = 10240
```

On success the startup log shows:

```text
2026-11-25T09:00:00.000Z INFO    MITM enabled: CA "CN=Rusty Conduit Switch Local CA, O=Homelab" valid until 2029-02-24T15:12:33.000Z; leaf certificate TTL 1h
```

Startup stops with `FATAL` (exit code `1`) if the CA cannot be read, the passphrase is wrong,
the certificate is expired or not yet valid, or the key does not match the certificate.

Rules for the CA options:

- Give **either** `--mitm-ca-cert` together with `--mitm-ca-key`, **or** `--mitm-ca-p12`.
  Mixing them is a fatal error.
- Give only one of `--mitm-ca-passphrase` and `--mitm-ca-passphrase-file`.
- `--mitm-cert-ttl` must be at least `10s`.

Upstream (origin) certificates are always checked against the operating system's trust store,
so interception never hides an invalid origin certificate from you.

### 3.1 MITM and routing

Interception works with every upstream profile. After the client's TLS is terminated, the
proxy routes the tunnel as usual and opens the origin TLS connection **through** the chosen
profile: `direct`, `socks5`, `socks4a`, `http`, or `https` (including failover chains and
composite profiles). A tunnel routed to `block` gets `403 Forbidden`.

With MITM on, the full `https://` URL of each decrypted request is visible, so URL rules
(`url_wildcard`, `url_regex`, `keyword`) can match HTTPS traffic too. When the routing table
contains URL rules, every decrypted request is routed separately, and requests on the same
client connection may go through different upstreams. Without URL rules, the route is chosen
once per tunnel from the host name and port. See the [User Guide](USER-GUIDE.md#6-routing-rules).

SOCKS connections are never intercepted; they stay transparent TCP tunnels. Start the server
with `--socks-block-web` (or `socks_block_web = true`) to reject HTTP and
TLS web traffic over SOCKS, so clients cannot bypass inspection that way.

The CA and every `[mitm]` setting are read at startup only. Hot-reload does not change them;
restart the server to switch CAs.

---

## 4. Trusting the CA

Clients must trust `ca.pem`, the certificate only, before they accept the certificates
rusty-conduit-switch generates. Install it **only** on devices whose traffic you intend to inspect.

### 4.1 Linux

**Debian, Ubuntu, and derivatives** (`ca-certificates`):

```sh
sudo cp ca.pem /usr/local/share/ca-certificates/rusty-conduit-switch-ca.crt   # must end in .crt
sudo update-ca-certificates
```

**Fedora, RHEL, CentOS, Arch, openSUSE** (`p11-kit` / `ca-certificates`):

```sh
sudo trust anchor --store ca.pem
# equivalent on Fedora/RHEL:
#   sudo cp ca.pem /etc/pki/ca-trust/source/anchors/rusty-conduit-switch-ca.pem && sudo update-ca-trust
```

**Chromium and Chrome on Linux** use the NSS database in your home directory, not the system
store:

```sh
# needs libnss3-tools (Debian/Ubuntu) or nss-tools (Fedora)
certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n "Rusty Conduit Switch Local CA" -i ca.pem
```

### 4.2 macOS

Add the CA to the System keychain as a trusted root. This needs an administrator account:

```sh
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain ca.pem
```

To do it in the GUI instead:

1. Open **Keychain Access**.
2. Drag `ca.pem` into the **System** keychain.
3. Double-click the certificate.
4. Expand **Trust** and set *When using this certificate* to **Always Trust**.

Safari, Chrome, curl (`/usr/bin/curl`), and most native apps use this trust setting.

### 4.3 Windows

Windows tools prefer a `.cer` file. Convert the certificate first. This step is optional,
because `certutil` also reads PEM:

```sh
openssl x509 -in ca.pem -outform der -out ca.cer
```

Then, in an **elevated** Command Prompt or PowerShell, install it for all users:

```bat
certutil -addstore -f Root ca.cer
```

Or install it for the current user only, without admin rights. Windows asks you to confirm:

```bat
certutil -user -addstore Root ca.cer
```

The PowerShell equivalent:

```powershell
Import-Certificate -FilePath .\ca.cer -CertStoreLocation Cert:\LocalMachine\Root
```

To use the GUI instead, run `certlm.msc` (machine) or `certmgr.msc` (user), open
**Trusted Root Certification Authorities → Certificates**, then choose
**All Tasks → Import…**. Edge, Chrome, and most Windows applications use this store.

### 4.4 Firefox (all platforms)

By default Firefox uses its own certificate store. Pick one of these options:

- **Import into Firefox:**
  1. Open **Settings → Privacy & Security → Certificates → View Certificates… → Authorities**.
  2. Click **Import…** and select `ca.pem`.
  3. Tick **Trust this CA to identify websites**.
- **Use the OS store (Windows and macOS):**
  1. Open `about:config`.
  2. Set `security.enterprise_roots.enabled` to `true`.
  3. Restart Firefox. It then trusts the CA you installed in [4.2](#42-macos) or
     [4.3](#43-windows).
- **Managed deployment:** in `policies.json`, set
  `"Certificates": { "ImportEnterpriseRoots": true }`, or
  `"Certificates": { "Install": ["/path/to/ca.pem"] }`.

### 4.5 Command-line tools and runtimes

Many tools bundle their own CA list or read an environment variable:

```sh
curl -x http://127.0.0.1:3128 --cacert ca.pem https://example.com/
export SSL_CERT_FILE=/path/to/ca-bundle-including-ca.pem   # OpenSSL-based tools
export REQUESTS_CA_BUNDLE=/path/to/ca-bundle-including-ca.pem  # Python requests
export NODE_EXTRA_CA_CERTS=/path/to/ca.pem                 # Node.js (adds to defaults)
git config --global http.sslCAInfo /path/to/ca-bundle-including-ca.pem
```

`SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, and `http.sslCAInfo` *replace* the default CA list. Point
them at a bundle that contains both the system roots and `ca.pem`. For example, on Debian or
Ubuntu, `/etc/ssl/certs/ca-certificates.crt` after you run `update-ca-certificates`.

Java applications use their own keystore:

```sh
keytool -importcert -noprompt -alias rusty-conduit-switch-ca -file ca.pem -cacerts -storepass changeit
```

### 4.6 Verifying interception

Start rusty-conduit-switch with MITM and an access log, then send a request through it that trusts
only your CA:

```sh
rusty-conduit-switch --mitm-ca-cert ca.pem --mitm-ca-key ca.key --http-access-log access.log &
curl -sS -o /dev/null -w '%{http_code}\n' -x http://127.0.0.1:3128 --cacert ca.pem https://example.com/
tail -n1 access.log
# ts=… kind=http client=127.0.0.1:… proto=https mitm=true method=GET target=https://example.com/ rule=<default> profile=direct upstream=direct status=200 …
```

If the client reports an unknown issuer, the CA is not trusted in that client's store.

Each leaf certificate rusty-conduit-switch presents has:

- issuer: your CA,
- one SAN: the requested host name or IP,
- validity from `now − 5m` to `now + --mitm-cert-ttl + 5m`.

Leaves are kept in memory only, for at most `--mitm-cert-ttl` and at most
`--mitm-cert-cache-max-entries` entries, and are never written to disk.

---

## 5. Removing the CA again

| Platform | Command |
| :--- | :--- |
| Debian/Ubuntu | `sudo rm /usr/local/share/ca-certificates/rusty-conduit-switch-ca.crt && sudo update-ca-certificates --fresh` |
| Fedora/RHEL/Arch | `sudo trust anchor --remove ca.pem` (or delete the file from `/etc/pki/ca-trust/source/anchors/` and run `sudo update-ca-trust`) |
| Linux NSS (Chromium) | `certutil -d sql:$HOME/.pki/nssdb -D -n "Rusty Conduit Switch Local CA"` |
| macOS | `sudo security remove-trusted-cert -d ca.pem` then `sudo security delete-certificate -c "Rusty Conduit Switch Local CA" /Library/Keychains/System.keychain` |
| Windows | `certutil -delstore Root "Rusty Conduit Switch Local CA"` (add `-user` for the per-user store) |
| Firefox | **View Certificates → Authorities**, select the CA, **Delete or Distrust…** |
| Java | `keytool -delete -alias rusty-conduit-switch-ca -cacerts -storepass changeit` |

After removing the CA from every client, destroy the private key (`ca.key`, `ca.enc.key`,
`ca.p12`, `ca.pass`) so nobody can use it again.
