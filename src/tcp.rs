use etherparse::{Ipv4HeaderSlice, TcpHeaderSlice};

pub struct State {}

impl Default for State {
    fn default() -> Self {
        State {}
    }
}

impl State {
    pub fn on_packet<'a>(
        &mut self,
        ip_header: Ipv4HeaderSlice<'a>,
        tcp_header: TcpHeaderSlice<'a>,
        _data: &'a [u8],
    ) {
        eprintln!(
            "{}:{} → {}:{} Read {:x} bytes of tcp",
            ip_header.source_addr(),
            tcp_header.source_port(),
            ip_header.destination_addr(),
            tcp_header.destination_port(),
            tcp_header.slice().len(),
        );
    }
}
