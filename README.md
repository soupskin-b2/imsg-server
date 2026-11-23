# imsg-server

An iMessage bridge for flip phones. The server talks to Apple through
[rustpush](https://github.com/OpenBubbles/rustpush) and keeps a small, low-power TLS push
connection open to each paired phone. The phone side ships in
[Messages Improved](https://github.com/thooton/wave_packages/tree/master/mods/messages) for the
Sonim XP3800.

Your phone number is registered with iMessage automatically: after pairing, the server asks the
phone to text Apple's registration gateway, the phone passes Apple's reply back, and the server
finishes the registration. Messages to iPhone users then go as iMessage; everyone else still gets
SMS.

## What you need

- A Linux server reachable from the internet on port 443, with a domain name pointing at it.
- A TLS certificate for that domain from a public CA (for example Let's Encrypt). Phones check it
  against their built-in trusted CAs.
- A registration relay (host and code) that provides iOS validation data, as used by OpenBubbles.
- The phone, with the SIM for the number you want to use.

## Install

Prebuilt Linux x86_64 binaries are published on the
[GitHub Releases](https://github.com/soupskin-b2/imsg-server/releases/latest) page:

```sh
curl -fsSLO https://github.com/soupskin-b2/imsg-server/releases/latest/download/imsg-server-linux-x86_64.tar.gz
tar -xzf imsg-server-linux-x86_64.tar.gz
sudo install -m 755 imsg-server /usr/local/bin/imsg-server
```

## Build

```sh
git clone https://github.com/soupskin-b2/imsg-server
cd imsg-server
scripts/setup.sh            # fetches rustpush and sets up its FairPlay key files
cargo build --release       # needs Rust, protoc and a C toolchain
sudo cp target/release/imsg-server /usr/local/bin/
```

rustpush is a git submodule; this repository does not include its code. `scripts/setup.sh` sets
up the FairPlay key files the same way rustpush's own CI does.

## Set up

```sh
sudo certbot certonly --standalone -d imsg.example.com
sudo mkdir -p /var/lib/imsg-server && cd /var/lib/imsg-server
sudo imsg-server init --domain imsg.example.com --relay-host https://relay.example.com --relay-code CODE
sudo imsg-server pair
```

`init` writes `config.toml` (it uses the Let's Encrypt certificate paths for the domain unless you
pass `--cert` and `--key`). `pair` prints a pairing code and starts the server. Both use
`config.toml` in the current folder; pass `-c /path/to/config.toml` to use another.

On the phone, open **Messages > Settings > Advanced settings > Apple (iMessage) settings**, enter
the server name and the code, and choose **Pair**. The phone then registers your number by
itself; it shows **iMessage is ready** when done.

A code works once, expires after 15 minutes, and stops working after 5 wrong tries. Run
`sudo imsg-server pair` in `/var/lib/imsg-server` again to pair another phone; if the server is
already running (for example as the service below), it picks up the new code.

## Run as a service

Once the phone shows **iMessage is ready**, stop `pair` with Ctrl-C and install the service:

```ini
# /etc/systemd/system/imsg-server.service
[Unit]
Description=imsg-server
After=network-online.target
Wants=network-online.target

[Service]
WorkingDirectory=/var/lib/imsg-server
ExecStart=/usr/local/bin/imsg-server run
Restart=always

[Install]
WantedBy=multi-user.target
```

```sh
sudo systemctl enable --now imsg-server
```

## Files

Everything the server keeps lives next to `config.toml`. Keep these private and back them up:

| Path | Contents |
| --- | --- |
| `config.toml` | Settings, relay code, and the hashed tokens of paired phones |
| `apple/` | Apple device identity and registration |
| `state/` | Per-phone message queues and the pending pairing code |

## Testing without Apple

`imsg-server run --no-apple` (or `pair --no-apple`) skips Apple. It simulates phone-number setup
(any `REG-RESP` is accepted) and echoes every sent message back, so you can try a phone end to end.

## Status

Pairing, the push protocol and the phone side are tested on an XP3800 against `--no-apple`. Relay
activation and phone-number registration with Apple have not yet been run against Apple's live
servers.

## License

AGPL-3.0-only. rustpush, fetched as a submodule, has its own license.
