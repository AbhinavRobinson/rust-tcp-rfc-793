use etherparse::{IpNumber, Ipv4Header, Ipv4HeaderSlice, TcpHeader, TcpHeaderSlice};

pub enum State {
    Closed,
    Listen,
    SynRcvd,
    Estab,
}

pub struct SendSequenceSpace {
    una: usize,
    nxt: usize,
    wnd: usize,
    up: bool,
    wl1: usize,
    wl2: usize,
    iss: usize,
}

pub struct RecvSequenceSpace {
    nxt: usize,
    wnd: usize,
    up: bool,
    ira: usize,
}

pub struct Connection {
    state: State,
    send: SendSequenceSpace,
    recv: RecvSequenceSpace,
}

impl Default for Connection {
    fn default() -> Self {
        Connection {
            // first impl, keeping default tcp state LISTEN
            state: State::Listen,
            send: todo!(),
            recv: todo!(),
        }
    }
}

impl Connection {
    pub fn debug_print<'a>(
        ip_header: &Ipv4HeaderSlice<'a>,
        tcp_header: &TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) {
        eprintln!(
            "{}:{} → {}:{} Read {} bytes of tcp",
            ip_header.source_addr(),
            tcp_header.source_port(),
            ip_header.destination_addr(),
            tcp_header.destination_port(),
            data.len()
        );
    }

    pub fn on_packet<'a>(
        &mut self,
        network_interface: &mut tun_tap::Iface,
        ip_header: Ipv4HeaderSlice<'a>,
        tcp_header: TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> std::io::Result<usize> {
        let mut buffer = [0u8; 1504];
        match self.state {
            State::Closed => Ok(0),
            State::Listen => {
                if !tcp_header.syn() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionRefused,
                        "",
                    ));
                }
                Connection::debug_print(&ip_header, &tcp_header, data);
                let mut syn_ack = TcpHeader::new(
                    tcp_header.destination_port(),
                    tcp_header.source_port(),
                    0,
                    0,
                );
                syn_ack.syn = true;
                syn_ack.ack = true;
                let ip = Ipv4Header::new(
                    syn_ack.header_len_u16(),
                    64,
                    IpNumber::TCP,
                    ip_header.destination(),
                    ip_header.source(),
                )
                .expect("Failed to create SYN ipv4 packet");
                let unwritten = {
                    let mut unwritten = &mut buffer[..];
                    let _ = ip.write(&mut unwritten);
                    let _ = syn_ack.write(&mut unwritten);
                    unwritten.len()
                };
                network_interface.send(&buffer[..unwritten])
            }
            State::SynRcvd => Ok(0),
            State::Estab => Ok(0),
        }
    }
}
