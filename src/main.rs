use std::io;

fn main() -> io::Result<()> {
    let nic = tun_tap::Iface::new("tun0", tun_tap::Mode::Tun)?;
    let mut buf = [0u8; 1504];
    let nbytes = nic.recv(&mut buf[..])?;
    eprintln!("Read {} : {:x?}", nbytes - 4, &buf[0..nbytes]);
    Ok(())
}
