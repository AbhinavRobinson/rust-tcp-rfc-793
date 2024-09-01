use std::io;

fn main() -> io::Result<()> {
    let network_interface = tun_tap::Iface::new("tun0", tun_tap::Mode::Tun)?;
    let mut buffer = [0u8; 1504];
    loop {
        let network_bytes = network_interface.recv(&mut buffer[..])?;
        let ether_protocol = u16::from_be_bytes([buffer[2], buffer[3]]);
        if ether_protocol != 0x0800 {
            // ignore packets other than ipv4
            continue;
        }
        match etherparse::Ipv4Slice::from_slice(&buffer[4..network_bytes]) {
            Ok(p) => {
                let header = p.header();
                let payload_len = header.payload_len().expect("Error parsing payload len");
                let source_addr = header.source_addr();
                let destination_addr = header.destination_addr();
                let protocol = header.protocol();
                let ttl = header.ttl();
                eprintln!(
                    "{} → {} Read {:x} bytes of proto: {:?} ttl: {:x}",
                    source_addr, destination_addr, payload_len, protocol, ttl,
                );
                if protocol != etherparse::IpNumber(0x06) {
                    // ignore packets other than tcp
                    continue;
                }
                let slice_len = p.header().slice().len();
                match etherparse::TcpHeaderSlice::from_slice(&buffer[4 + slice_len..]) {
                    Ok(h) => {
                        let destination_port = h.destination_port();
                        eprintln!(
                            "{} → {} Read {:x} bytes of TCP to port: {}",
                            source_addr, destination_addr, slice_len, destination_port,
                        );
                    }
                    Err(e) => {
                        eprintln!("Errored Tcp packet {:?}", e)
                    }
                }
            }
            Err(e) => {
                eprintln!("Errored packet {:?}", e)
            }
        }
    }
}
