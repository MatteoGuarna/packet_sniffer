use etherparse::{IpHeader, PacketHeaders, TransportHeader};
use pcap::Device;

fn main() {
    let devs = Device::list().unwrap();
    let d = devs.get(1).unwrap();
    let mut cap = d.clone().open().unwrap();
    /*
    while let Ok(packet) = cap.next() {
        println!("received packet! {:?}", packet);
    }<*/
    let packet = cap.next().unwrap();
    match PacketHeaders::from_ethernet_slice(&packet) {
        Err(value) => println!("Err {:?}", value),
        Ok(value) => {
            match value.ip.unwrap() {
                IpHeader::Version4(h, _e) => {
                    println!("IP Protocol: IPv4");
                    println!("-- Destination IP: {}.{}.{}.{}", h.destination[0],h.destination[1],h.destination[2],h.destination[3]);
                    println!("-- Source IP: {}.{}.{}.{}", h.source[0],h.source[1],h.source[2],h.source[3]);
                }
                IpHeader::Version6(h, _e) => {
                    println!("IP Protocol: IPv6");
                    println!("-- Destination IP: {:#01x}{:#01x}:{:#01x}{:#01x}:{:#01x}{:#01x}:{:#01x}{:#01x}:{:#01x}{:#01x}:{:#01x}{:#01x}:{:#01x}{:#01x}:{:#01x}{:#01x}", 
                        h.destination[0],h.destination[1],h.destination[2],h.destination[3],
                        h.destination[4],h.destination[5],h.destination[6],h.destination[7],
                        h.destination[8],h.destination[9],h.destination[10],h.destination[11],
                        h.destination[12],h.destination[13],h.destination[14],h.destination[15]
                    );
                    println!("-- Source IP: {:#01x}{:#01x}:{:#01x}{:#01x}:{:#01x}{:#01x}:{:#01x}{:#01x}:{:#01x}{:#01x}:{:#01x}{:#01x}:{:#01x}{:#01x}:{:#01x}{:#01x}", 
                        h.source[0],h.source[1],h.source[2],h.source[3],
                        h.source[4],h.source[5],h.source[6],h.source[7],
                        h.source[8],h.source[9],h.source[10],h.source[11],
                        h.source[12],h.source[13],h.source[14],h.source[15] 
                    );
                }
            }
            match value.transport.unwrap() {
               TransportHeader::Tcp(h) => {
                    println!("Transport Protocol: TCP");
                    println!("-- Destination Port: {}", h.destination_port);
                    println!("-- Source Port: {}", h.source_port);
               },
               TransportHeader::Udp(h) => {
                    println!("Transport Protocol: UDP");
                    println!("-- Destination Port: {}", h.destination_port);
                    println!("-- Source Port: {}", h.source_port);
               },
               _ => ()
            }
        }
    }
}
