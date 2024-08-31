use std::io::Read;

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let mut config = tun2::Configuration::default();
    config
        .address((10, 0, 0, 9))
        .netmask((255, 255, 255, 0))
        .destination((10, 0, 0, 1))
        .up();

    let mut dev = tun2::create(&config)?;
    let mut buf = [0; 4096];

    loop {
        let amount = dev.read(&mut buf)?;
        println!("{:?}", &buf[0..amount]);
    }
}
