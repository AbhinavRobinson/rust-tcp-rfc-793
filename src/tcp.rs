use etherparse::{IpNumber, Ipv4Header, Ipv4HeaderSlice, TcpHeader, TcpHeaderSlice};

pub enum State {
    // Closed,
    // Listen,
    SynRcvd,
    Estab,
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
    ip: Ipv4Header,
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
        let mut connection = Connection {
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
            ip: Ipv4Header::new(
                0,
                64,
                IpNumber::TCP,
                ip_header.destination(),
                ip_header.source(),
            )
            .expect("Failed to create SYN ipv4 packet"),
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
        // Set Ip header length
        //
        let _ = connection.ip.set_payload_len(syn_ack.header_len() + 0);
        //
        // Compute checksum
        //
        syn_ack.checksum = syn_ack
            .calc_checksum_ipv4(&connection.ip, &[])
            .expect("failed to calc checksum");
        //
        // Response Writer
        //
        let unwritten = {
            let mut unwritten = &mut buffer[..];
            let _ = connection.ip.write(&mut unwritten);
            let _ = syn_ack.write(&mut unwritten);
            unwritten.len()
        };
        //
        // Send ACK Reponse
        //
        let _ = network_interface.send(&buffer[..unwritten]);
        Ok(Some(connection))
    }

    pub fn on_packet<'a>(
        &mut self,
        network_interface: &mut tun_tap::Iface,
        ip_header: Ipv4HeaderSlice<'a>,
        tcp_header: TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> std::io::Result<()> {
        // Do acceptable ACK check
        // UNA < ACK =< NXT concidering wrapping arithmatic
        let ackn = tcp_header.acknowledgment_number();
        let unan = self.send.una;
        let nxtn = self.send.nxt;
        if unan < ackn {
            // VALID
            // 0 ---- U ---- A ---- N ---- 0
            // 0 ---- N ---- U ---- A ---- 0
            //
            // INVALID
            // 0 ---- U ---- N ---- A ---- 0
            if unan <= nxtn && nxtn < ackn {
                // Ignore connection
                return Ok(());
            }
        } else {
            // VALID
            // 0 ---- A ---- N ---- U ---- 0
            //
            // INVALID
            // 0 ---- A ---- U ---- N ---- 0
            if ackn <= unan && unan < nxtn {
                // Ignore connection
                return Ok(());
            }
        }

        match self.state {
            State::SynRcvd => Ok(()),
            State::Estab => {
                unimplemented!()
            }
        }
    }
}
