use etherparse::{IpHeader, PacketHeaders, TransportHeader};
use pcap::Device;
use sprintf::sprintf;

fn main() {
    let devs = Device::list().unwrap();
    let d = devs.get(1).unwrap();
    let mut cap = d.clone().open().unwrap();

    println!(
        "{0: <12} | {1: <15} | {2: <15} | {3: <18} | {4: <15} | {5: <11}",
        "IP Protocol", "Destination IP", "Source IP", "Transport Protocol", "Destination Port", "Source Port"
    );
    /*
    while let Ok(packet) = cap.next() {
        println!("received packet! {:?}", packet);
    }<*/

    
    let packet = cap.next().unwrap();
    println!("{}.{}", packet.header.ts.tv_sec, packet.header.ts.tv_usec);
    match PacketHeaders::from_ethernet_slice(&packet) {
        Err(value) => println!("Err {:?}", value),
        Ok(value) => {
            match value.ip.unwrap() {
                IpHeader::Version4(h, _e) => {
                    let dest = sprintf!("%d.%d.%d.%d", h.destination[0],h.destination[1],h.destination[2],h.destination[3]);
                    let sour = sprintf!("%d.%d.%d.%d", h.source[0],h.source[1],h.source[2],h.source[3]);
                    print!("{0: <12} | {1:<15} | {2:<15} |", "IPv4", dest.unwrap(), sour.unwrap());
                }
                IpHeader::Version6(h, _e) => {
                    print!("  {0: <10} |", "IPv6");
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
                    print!(" {0: <18} |", "TCP");
                    print!(" {0: <16} |", h.destination_port);
                    println!(" {0: <11} |", h.source_port);
               },
               TransportHeader::Udp(h) => {
                    print!(" {0: <18} |", "UDP");
                    print!(" {0: <16} |", h.destination_port);
                    println!(" {0: <11}", h.source_port);
               },
               _ => ()
            }
        }
    }
}
