use std::io;

fn main() -> io::Result<()> {
    // Initialize Tun network interface
    let nic = tun_tap::Iface::new("tun0", tun_tap::Mode::Tun)?;
    let mut buf = [0u8; 1504];
    // Write packet to buffer
    let nbytes = nic.recv(&mut buf[..])?;
    eprintln!("Read {} bytes: {:x?}", nbytes, &buf[..nbytes]);
    Ok(())
}
