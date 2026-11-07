use std::{error::Error, time::Instant};

use pcap::{Capture, Error as PcapError, Linktype};

use crate::{alert::Webhook, detect::{Detector, Traffic}, rules::Protocol};

pub fn run(iface: &str, mut detector: Detector, webhook: Webhook) -> Result<(), Box<dyn Error>> {
    let mut capture = Capture::from_device(iface)?
        .promisc(false)
        .snaplen(128)
        .timeout(1000)
        .open()?;

    if capture.get_datalink() != Linktype::ETHERNET {
        return Err(format!("{iface}: only Ethernet link-layer packets are supported").into());
    }

    loop {
        match capture.next_packet() {
            Ok(packet) => {
                let Some(traffic) = parse_packet(packet.data) else {
                    continue;
                };

                for detection in detector.observe(traffic, Instant::now()) {
                    println!(
                        "DETECTION: {} | {}:{} | {} packets in {}s (threshold {})",
                        detection.rule,
                        detection.protocol,
                        detection.port,
                        detection.packets,
                        detection.window_secs,
                        detection.threshold
                    );

                    if let Err(error) = webhook.send(&detection) {
                        eprintln!("webhook delivery failed: {error}");
                    }
                }
            }
            Err(PcapError::TimeoutExpired) => continue,
            Err(error) => return Err(error.into()),
        }
    }
}

fn parse_packet(frame: &[u8]) -> Option<Traffic> {
    let mut kind = u16::from_be_bytes(frame.get(12..14)?.try_into().ok()?);
    let mut offset = 14;

    while kind == 0x8100 || kind == 0x88a8 {
        kind = u16::from_be_bytes(frame.get(offset + 2..offset + 4)?.try_into().ok()?);
        offset += 4;
    }

    let ip = frame.get(offset..)?;
    let (next, payload) = match kind {
        0x0800 => ipv4_payload(ip)?,
        0x86dd => ipv6_payload(ip)?,
        _ => return None,
    };

    let protocol = match next {
        6 => Protocol::Tcp,
        17 => Protocol::Udp,
        _ => return None,
    };

    let ports = payload.get(..4)?;
    Some(Traffic {
        protocol,
        src_port: u16::from_be_bytes([ports[0], ports[1]]),
        dst_port: u16::from_be_bytes([ports[2], ports[3]]),
    })
}

fn ipv4_payload(ip: &[u8]) -> Option<(u8, &[u8])> {
    if ip.len() < 20 || ip[0] >> 4 != 4 {
        return None;
    }

    let header_len = ((ip[0] & 0x0f) as usize) * 4;
    if header_len < 20 || ip.len() < header_len {
        return None;
    }

    let fragments = u16::from_be_bytes([ip[6], ip[7]]);
    if fragments & 0x1fff != 0 {
        return None;
    }

    Some((ip[9], ip.get(header_len..)?))
}

fn ipv6_payload(ip: &[u8]) -> Option<(u8, &[u8])> {
    if ip.len() < 40 || ip[0] >> 4 != 6 {
        return None;
    }

    let mut next = ip[6];
    let mut offset = 40usize;

    for _ in 0..8 {
        let header = ip.get(offset..)?;
        let length = match next {
            0 | 43 | 60 => (usize::from(*header.get(1)?) + 1) * 8,
            44 => {
                let fields = header.get(..8)?;
                if u16::from_be_bytes([fields[2], fields[3]]) & 0xfff8 != 0 {
                    return None;
                }
                8
            }
            51 => (usize::from(*header.get(1)?) + 2) * 4,
            _ => return Some((next, header)),
        };
        next = *header.first()?;
        offset += length;
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_tcp_ports() {
        let mut frame = vec![0; 14 + 20 + 4];
        frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        frame[14] = 0x45;
        frame[23] = 6;
        frame[34..38].copy_from_slice(&[0, 22, 0x9c, 0x40]);

        let packet = parse_packet(&frame).unwrap();
        assert_eq!(packet.protocol, Protocol::Tcp);
        assert_eq!(packet.src_port, 22);
        assert_eq!(packet.dst_port, 40000);
    }

    #[test]
    fn ignores_truncated_frames() {
        assert!(parse_packet(&[0; 10]).is_none());
    }
}
