# imsg-server

An iMessage bridge for flip phones. The server talks to Apple through
[rustpush](https://github.com/OpenBubbles/rustpush), hosts its own registration relay on
the same TLS port, and keeps a small, low-power TLS push connection open to each paired phone. The
phone side ships in
[Messages Improved](https://github.com/thooton/wave_packages/tree/master/mods/messages) for the
Sonim XP3800.

Your phone number is registered with iMessage automatically: after pairing, the server asks the
phone to text Apple's registration gateway, the phone passes Apple's reply back, and the server
finishes the registration. Messages to iPhone users then go as iMessage; everyone else still gets
SMS.

What crosses the bridge:

- **Text**, 1:1 and group, with mentions, inline replies (shown with a short quote of the
  original) and subjects. Formatting and effects arrive as plain text.
- **Photos, videos, voice messages, audio and contacts**, both ways. The server downloads each
  attachment from Apple and gives the phone a screen-size preview it can show: JPEG or PNG at
  most 640 px (HEIC decoded), 240p H.264 video, AAC audio. "Save attachment" on the phone fetches
  the full-size file (HEIC becomes a full-resolution JPEG, HEVC video becomes H.264). What the
  phone sends (JPEG, 3GP, AMR) is converted to what iPhones show inline; a voice recording sent on
  its own arrives as an iPhone audio message (`Audio Message.caf`, Opus), so like any audio message
  it may expire on the iPhone unless kept. Other files (PDFs, zips, ...) arrive as
  `[File: name, size]` with no preview, and the phone downloads the original on demand.
- **Tapbacks**, shown as badges on the message, both ways (the phone sends the six standard ones).
- **Edits** (`... (edited)`, earlier versions kept), **unsends** (the message stays, marked
  `Unsent`), and group **renames, member changes and photo changes** as notices in the conversation.
- **Editing and unsending your own messages** from the phone, within Apple's limits (edit within
  15 minutes, up to 5 times; unsend within 2 minutes). Needs Messages Improved 1.8.0 or later.
- iMessage apps, Apple Cash, Check In and similar show a readable label such as `[Apple Cash]`.

## What you need

- A Linux server reachable from the internet on port 443, with a domain name pointing at it.
- A TLS certificate for that domain from a public CA (for example Let's Encrypt). Both the flip
  phone and the iPhone check it against their built-in trusted CAs.
- A jailbroken iPhone running [OpenBubbles/relayserver](https://github.com/OpenBubbles/relayserver),
  which supplies iOS validation data to this server's built-in relay.
- The flip phone, with the SIM for the number you want to use.
- `ffmpeg` and `heif-dec` on the server for photos and videos:
  `sudo apt install ffmpeg libheif-examples`. Without ffmpeg attachments arrive as placeholders;
  without `heif-dec`, ffmpeg older than 8.1 (Debian 13 has 7.1) shows only one 512 px tile of
  each iPhone photo.

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
scripts/setup.sh            # fetches and patches rustpush
cargo build --release       # needs Rust, protoc and a C toolchain
sudo cp target/release/imsg-server /usr/local/bin/
```

rustpush is a git submodule; this repository does not include its code. `scripts/setup.sh` applies
`patches/rustpush-runtime-fairplay.patch`, which makes rustpush load its FairPlay certificates at
runtime instead of compiling them in, so builds (including the published release) contain no keys.

## Set up

```sh
sudo certbot certonly --standalone -d imsg.example.com
sudo mkdir -p /var/lib/imsg-server && cd /var/lib/imsg-server
sudo imsg-server init --domain imsg.example.com
```

`init` writes `config.toml` (using the Let's Encrypt certificate paths for `--domain` unless you
pass `--cert` and `--key`), initializes the built-in relay credentials, and prints the WebSocket
provider URL for `OpenBubbles/relayserver`:

```text
wss://imsg.example.com/api/v1/provider?t=<token>
```

On the jailbroken iPhone (SSH into the phone as `root` or `mobile`), write `/var/mobile/config.json`
with that URL and restart the `relayserver` LaunchDaemon (`KeepAlive` restarts it automatically
when killed):

```sh
printf '{"url":"wss://imsg.example.com/api/v1/provider?t=<token>","state":null}\n' > /var/mobile/config.json
killall relayserver
```

(Or reload it explicitly with `launchctl unload /Library/LaunchDaemons/dev.copper.relayserver.plist
&& launchctl load /Library/LaunchDaemons/dev.copper.relayserver.plist`.)

You can print the URL again at any time with `sudo imsg-server relay-url`. When `relayserver`
connects for the first time (or migrates from Beeper's relay), the built-in relay issues it a fresh
code and secret automatically, `relayserver` saves them into `/var/mobile/config.json`, and
`imsg-server` locks to that single provider.

To activate a new device with Apple, `imsg-server` needs FairPlay certificates in
`<apple_dir>/fairplay/` (by default `/var/lib/imsg-server/apple/fairplay/`). Put each certificate
chain in `<name>.crt` (leaf first, then intermediates, ending at Apple Root CA; PEM or DER) with
its private key beside it as `<name>.key` (PEM or DER), then restart. With several pairs, each
activation picks one at random. They are loaded at startup, checked (key matches leaf, chain in
order), and only used for activation: an install that is already activated runs without them.

Next, pair the flip phone:

```sh
sudo imsg-server pair
```

`pair` prints a pairing code and starts the server. Both `init` and `pair` use `config.toml` in the
current folder; pass `-c /path/to/config.toml` to use another.

On the phone, open **Messages > Settings > Advanced settings > Apple (iMessage) settings**, enter
the server name and the code, and choose **Pair**. The phone then registers your number by itself;
it shows **iMessage is ready** when done.

A code works once, expires after 15 minutes, and stops working after 5 wrong tries. Run
`sudo imsg-server pair` in `/var/lib/imsg-server` again to pair another phone; if the server is
already running (for example as the service below), it picks up the new code.

## Automatic renewal and recovery

Apple's phone-number authentication certificate has a finite lifetime and can also be invalidated
early (IDS error 6005). `imsg-server` handles both automatically:

- **Proactive renewal:** by default, 7 days before the phone auth certificate expires (`[renewal]
  lead_days = 7` in `config.toml`), the server asks the connected flip phone to perform the SMS
  registration handshake while the existing login still works, then swaps in the renewed credentials
  without an outage. If the phone is offline, renewal waits until it connects (or retries daily if an
  attempt times out).
- **Automatic recovery:** if Apple returns IDS error 6005, the server immediately schedules SMS
  re-authentication and rebuilds the iMessage session once the phone completes it.
- **Keep the iPhone provider online:** Apple IDS re-registration requests validation data from the
  built-in relay. If the iPhone provider is offline, `imsg-server` retries automatically and
  triggers an immediate re-registration as soon as the iPhone reconnects.

Apple currently issues the phone auth certificate for 10 years, so in practice the SMS renewal runs
after a 6005, while the IDS registration is renewed through the relay every few weeks. The phone's
Renewal line (REG_INFO `renew_at_ms`) shows whichever of the two comes first, and "Relay offline"
when the iPhone provider is not connected (the next re-registration then needs it back).

**SMS cost notice:** each phone-number registration and renewal sends an outgoing SMS from the flip
phone to Apple's carrier registration gateway (often an international number, depending on your
carrier). Some mobile plans charge per international SMS.

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
| `config.toml` | Settings, renewal lead time, and the hashed tokens of paired phones |
| `apple/` | Apple device identity, registration, and built-in relay secret/provider state |
| `state/` | Per-phone message queues, pending pairing code, and `apple_status.json` |
| `state/media/` | Attachments (originals, previews and full-size copies), kept 30 days |

Attachment handling can be tuned in `config.toml`:

```toml
[media]
retention_days = 30          # how long "Save attachment" can still fetch the full-size file
# ffmpeg = "/usr/bin/ffmpeg" # ffprobe is looked up next to it
```

Messages wait in `state/` for a phone that's offline, up to 5000 per phone (or 64 MB); beyond that
the oldest are dropped. A paired phone that hasn't connected for 90 days is taken to be gone (for
example one that was paired again and got a new id) and gets nothing queued; the log says which,
and you can remove its `[[clients]]` entry from `config.toml`.

Losing `state/` (a new server, a restore from an old backup) doesn't confuse the phone: each side's
message numbering carries a random epoch, so when either side's state is new the other starts
over instead of dropping its messages as already seen. Messages that were still queued in the lost
state are gone, nothing else.

The server and the phone must run the same protocol version: protocol 2 (this release) needs
Messages Improved 1.5.0 or later, and Messages Improved 1.6.2 or later needs this release (its
HELLO carries the epochs; older protocol 2 servers refuse it). Update the server first, then the
phone; messages still queued for a protocol 1 phone are not readable by the new one.

## Testing without Apple

`imsg-server run --no-apple` (or `pair --no-apple`) skips Apple. It still runs the built-in relay
(so you can test `relayserver` connectivity), simulates phone-number setup (any `REG-RESP` is accepted;
the number is kept in `state_dir/echo_handle`, so a set-up phone stays set up across restarts),
and echoes every sent message back, attachments included. A message starting with a command makes
the other side act instead:

| Send | The other side |
| --- | --- |
| `/react 0`…`/react 5`, `/react 🔥` | reacts to it (love, like, dislike, laugh, emphasize, question, or an emoji) |
| `/reply text` | answers with an inline reply to it |
| `/edit text`, `/unsend` | edits or unsends its last echoed message |
| `/photo`, `/video`, `/voice`, `/sticker` | sends a 12 MP photo, a 1080p MOV, a CAF voice message or a PNG sticker (needs ffmpeg) |
| `/file` | sends a 150 KB PDF (a file with no preview, downloaded on demand) |
| `/photos` | sends one message with four attachments (photo, sticker, photo, video) |

Edits and unsends of your own messages are accepted (nothing is sent back); an edit to `/fail` is
refused, to try the phone's error message.
| `/group text` | starts a group with you and a third person; the next group commands act on it |
| `/gsay text` | says something in that group |
| `/rename name`, `/icon` | renames the group, changes its photo |
| `/add handle`, `/remove handle` | adds or removes a group member (`tel:+1…` or `mailto:…`) |

Messages Improved's `tools/testing/imessage_interop_test.py` drives this mode end to end.

## License

AGPL-3.0-only. rustpush, fetched as a submodule, has its own license.
