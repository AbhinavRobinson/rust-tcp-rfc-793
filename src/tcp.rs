use etherparse::{IpNumber, Ipv4Header, Ipv4HeaderSlice, TcpHeader, TcpHeaderSlice};

pub enum State {
    // Closed,
    // Listen,
    SynRcvd,
    // Estab,
}

pub struct SendSequenceSpace {
    una: u32,
    nxt: u32,
    wnd: u16,
    up: bool,
    wl1: u16,
    wl2: u16,
    iss: u32,
}

pub struct RecvSequenceSpace {
    nxt: u32,
    wnd: u16,
    up: bool,
    irs: u32,
}

pub struct Connection {
    state: State,
    send: SendSequenceSpace,
    recv: RecvSequenceSpace,
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

    pub fn accept<'a>(
        network_interface: &mut tun_tap::Iface,
        ip_header: Ipv4HeaderSlice<'a>,
        tcp_header: TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> std::io::Result<Option<Self>> {
        let mut buffer = [0u8; 1504];
        if !tcp_header.syn() {
            // Only accept SYN Packet for new connection
            return Ok(None);
        }
        Connection::debug_print(&ip_header, &tcp_header, data);
        // @dev should technically be "random"
        let iss = 0;
        let connection = Connection {
            state: State::SynRcvd,
            send: SendSequenceSpace {
                iss,
                una: iss,
                nxt: iss + 1,
                wnd: 10,
                up: false,
                // DUNNO YET
                wl1: 0,
                wl2: 0,
            },
            recv: RecvSequenceSpace {
                irs: tcp_header.sequence_number(),
                nxt: tcp_header.sequence_number() + 1,
                wnd: tcp_header.window_size(),
                up: false,
            },
        };
        //
        // Build ACK Packet
        //
        let mut syn_ack = TcpHeader::new(
            tcp_header.destination_port(),
            tcp_header.source_port(),
            connection.send.iss,
            connection.send.wnd,
        );
        syn_ack.acknowledgment_number = connection.recv.nxt;
        syn_ack.syn = true;
        syn_ack.ack = true;
        //
        // Build IPv4 Header
        //
        let ip = Ipv4Header::new(
            syn_ack.header_len_u16(),
            64,
            IpNumber::TCP,
            ip_header.destination(),
            ip_header.source(),
        )
        .expect("Failed to create SYN ipv4 packet");
        //
        // Compute checksum
        //
        syn_ack.checksum = syn_ack
            .calc_checksum_ipv4(&ip, &[])
            .expect("failed to calc checksum");
        //
        // Response Writer
        //
        let unwritten = {
            let mut unwritten = &mut buffer[..];
            let _ = ip.write(&mut unwritten);
            let _ = syn_ack.write(&mut unwritten);
            unwritten.len()
        };
        //
        // Send ACK Reponse
        //
        let _ = network_interface.send(&buffer[..unwritten]);
        Ok(Some(connection))
    }

    // TODO
    // Handle ACK (3rd Handshake) Packet and FIN (Close connection) Packet
    pub fn on_packet<'a>(
        &mut self,
        _network_interface: &mut tun_tap::Iface,
        _ip_header: Ipv4HeaderSlice<'a>,
        _tcp_header: TcpHeaderSlice<'a>,
        _data: &'a [u8],
    ) -> std::io::Result<()> {
        Ok(())
    }
}
