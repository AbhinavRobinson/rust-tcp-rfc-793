use std::{
    collections::{hash_map::Entry, HashMap},
    io,
    net::Ipv4Addr,
};

mod tcp;

#[derive(Eq, Hash, PartialEq, Debug, Clone, Copy)]
struct IPQuad {
    src: (Ipv4Addr, u16),
    dst: (Ipv4Addr, u16),
}

fn main() -> io::Result<()> {
    //
    // Hold connections instances
    //
    let mut connections: HashMap<IPQuad, tcp::Connection> = Default::default();
    //
    // Start Tun Interface
    //
    let mut network_interface = tun_tap::Iface::without_packet_info("tun0", tun_tap::Mode::Tun)
        .expect("Failed to create Tun interface."); // Linux only
    let mut buffer = [0u8; 1504];
    loop {
        let network_bytes = network_interface
            .recv(&mut buffer[..])
            .expect("Failed to read network bytes.");
        //
        // Parse IP Header
        //
        match etherparse::Ipv4HeaderSlice::from_slice(&buffer[..network_bytes]) {
            Ok(ip_header) => {
                if ip_header.protocol() != etherparse::IpNumber(0x06) {
                    continue; // ignore packets other than tcp
                }
                //
                // Parse TCP Header
                //
                match etherparse::TcpHeaderSlice::from_slice(
                    &buffer[ip_header.slice().len()..network_bytes],
                ) {
                    Ok(tcp_header) => {
                        //
                        // Offset of packet data
                        //
                        let data_from = ip_header.slice().len() + tcp_header.slice().len();
                        match connections.entry(IPQuad {
                            src: (ip_header.source_addr(), tcp_header.source_port()),
                            dst: (ip_header.destination_addr(), tcp_header.destination_port()),
                        }) {
                            Entry::Occupied(mut c) => {
                                //
                                // Parse next Packet on existing connection
                                //
                                let _ = c.get_mut().on_packet(
                                    &mut network_interface,
                                    ip_header,
                                    tcp_header,
                                    &buffer[data_from..network_bytes],
                                );
                            }
                            Entry::Vacant(e) => {
                                //
                                // Parse first (SYN) Packet of new connection
                                //
                                if let Some(c) = tcp::Connection::accept(
                                    &mut network_interface,
                                    ip_header,
                                    tcp_header,
                                    &buffer[data_from..network_bytes],
                                )? {
                                    e.insert(c);
                                };
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Errored parsing TCP packet {:?}", e)
                    }
                }
            }
            Err(..) => (),
        }
    }
}
