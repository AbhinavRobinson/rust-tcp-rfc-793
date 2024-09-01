use std::{collections::HashMap, io, net::Ipv4Addr};

mod tcp;

#[derive(Eq, Hash, PartialEq, Debug, Clone, Copy)]
struct IPQuad {
    src: (Ipv4Addr, u16),
    dst: (Ipv4Addr, u16),
}

fn main() -> io::Result<()> {
    let mut connections: HashMap<IPQuad, tcp::Connection> = Default::default();
    let mut network_interface =
        tun_tap::Iface::new("tun0", tun_tap::Mode::Tun).expect("Failed to create Tun interface."); // Linux only
    let mut buffer = [0u8; 1504];
    loop {
        let network_bytes = network_interface
            .recv(&mut buffer[..])
            .expect("Failed to read network bytes.");
        let ether_protocol = u16::from_be_bytes([buffer[2], buffer[3]]);
        if ether_protocol != 0x0800 {
            continue; // ignore packets other than ipv4
        }
        match etherparse::Ipv4HeaderSlice::from_slice(&buffer[4..network_bytes]) {
            Ok(ip_header) => {
                if ip_header.protocol() != etherparse::IpNumber(0x06) {
                    continue; // ignore packets other than tcp
                }
                match etherparse::TcpHeaderSlice::from_slice(
                    &buffer[4 + ip_header.slice().len()..network_bytes],
                ) {
                    Ok(tcp_header) => {
                        let data_from = 4 + ip_header.slice().len() + tcp_header.slice().len(); // data start point = (headers) + offset
                        connections
                            .entry(IPQuad {
                                src: (ip_header.source_addr(), tcp_header.source_port()),
                                dst: (ip_header.destination_addr(), tcp_header.destination_port()),
                            })
                            .or_default()
                            .on_packet(
                                &mut network_interface,
                                ip_header,
                                tcp_header,
                                &buffer[data_from..network_bytes],
                            )?;
                    }
                    Err(e) => {
                        eprintln!("Errored parsing TCP packet {:?}", e)
                    }
                }
            }
            Err(e) => {
                eprintln!("Errored parsing IP packet {:?}", e)
            }
        }
    }
}
