# Watchline

Watchline is a Rust packet monitor for detecting traffic bursts. It watches an interface, keeps a rolling counter for each rule, prints detections to stdout, and optionally posts them to a webhook. It does not inspect application content or store captured packets.

## Build

Install Rust and Cargo using rustup. Packet capture requires libpcap. On macOS, install the Xcode Command Line Tools first. On Debian or Ubuntu, install `libpcap-dev` and `pkg-config`.

From the project directory, run:

```sh
cargo build --release
cargo test
```

## Run

On a Mac with an `en0` interface, start the monitor with:

```sh
sudo cargo run --release -- --iface en0 --rules rules/example.toml
```

Find your interface with `ifconfig` on macOS or `ip link` on Linux. Press Ctrl+C to stop. If sudo cannot find Cargo, run the already-built executable with `sudo ./target/release/watchline --iface en0 --rules rules/example.toml`.

## Screenshots

<img width="1440" height="900" alt="Screenshot 2026-11-10 at 19 31 16" src="https://github.com/user-attachments/assets/bbfb03ce-be37-4e65-a818-dc7c603af79c" />

## Rules and alerts

Edit `rules/example.toml` to change names, protocols, ports, thresholds, or window lengths. Protocols are TCP or UDP. Packets count when either endpoint uses the specified port. An alert fires when the counter reaches its threshold. Repeated alerts for that rule are suppressed for one full window.

To enable webhook delivery, pass `WEBHOOK_URL` through sudo:

```sh
sudo WEBHOOK_URL='https://your-endpoint.example/events' cargo run --release -- --iface en0 --rules rules/example.toml
```

Webhook requests contain rule metadata and packet counts, never packet bodies. Failed requests are reported on stderr. Watchline is a rate monitor, not a replacement for an intrusion detection system. Capture only networks you administer or have permission to monitor.
