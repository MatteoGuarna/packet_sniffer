pub mod packet_sniffer {
    use etherparse::{IpHeader, PacketHeaders, TransportHeader};
    use pcap::Device;
    use sprintf::sprintf;
    use std::sync::{Condvar, Arc, Mutex};
    use std::time::{Duration, Instant};
    use std::thread;
    use std::sync::mpsc::{channel, Receiver, Sender};
    use std::fmt::{Display, Formatter, Result};

    #[derive(PartialEq)]
    enum IpV {
        V4,
        V6,
    }
    
    #[derive(PartialEq)]
    enum Transport {
        TCP,
        UDP,
    }
    struct Connection {
        l3: IpV,
        ip_1: String,
        ip_2: String,
        l4: Transport,
        port_1: String,
        port_2: String,
        ts_start: String,
        ts_end: String,
        bytes: u32,
    }

    impl Display for IpV {
        fn fmt(&self, f: &mut Formatter) -> Result{
            match *self {
                IpV::V4 => write!(f, "IPv4"),
                IpV::V6 => write!(f, "IPv6")
            }
        }
    }

    impl Display for Transport {
        fn fmt(&self, f: &mut Formatter) -> Result{
            match *self {
                Transport::TCP => write!(f, "TCP"),
                Transport::UDP => write!(f, "UDP")
            }
        }
    }
    

    impl Connection {
        fn new(
            l3: u8,
            ip_1: String,
            ip_2: String,
            l4: u8,
            port_1: String,
            port_2: String,
            ts_start: String,
            ts_end: String,
            bytes: u32,
        ) -> Self {
            let mut ip = IpV::V4;

            if l3 != 4 {
                ip = IpV::V6;
            }

            let mut t = Transport::TCP;
            if l4 != 0 {
                t = Transport::UDP;
            }

            Self {
                l3: ip,
                ip_1,
                ip_2,
                l4: t,
                port_1,
                port_2,
                ts_start,
                ts_end,
                bytes,
            }
        }

        fn update(&mut self, new_ts_end: String, new_bytes: u32) {
            self.ts_end = new_ts_end;
            self.bytes += new_bytes;
        }
    }

    impl PartialEq for Connection {
        fn eq(&self, other: &Self) -> bool {
            if self.l4 == other.l4
                && (self.ip_1 == other.ip_1
                    && self.ip_2 == other.ip_2
                    && self.port_1 == other.port_1
                    && self.port_2 == other.port_2)
                || (self.ip_1 == other.ip_2
                    && self.ip_2 == other.ip_1
                    && self.port_1 == other.port_2
                    && self.port_2 == other.port_1)
            {
                return true;
            } else {
                return false;
            }
        }
    }
    
    struct Status{
        time_interval: f64,
        start_time: Instant,
        pause_time: Instant,
        pause: bool,
    }
    
    struct Waiting{
        state: Mutex<Status>,
        cv: Condvar
    }
    
    pub struct Sniffer{
        file_name: String,
        dev: usize,
        connections: Vec<Connection>,
        waiter: Arc<Waiting>
    }

    impl Sniffer {
        pub fn new(file_name: String, dev: usize, time_interval: f64) -> Self {
            
            let s= Mutex::new(Status{
                time_interval,
                start_time: Instant::now(),
                pause_time: Instant::now(),
                pause: false
            });

            let wait= Arc::new(Waiting{
                state: s,
                cv: Condvar::new()    
            });
            
            return Sniffer {
                file_name,
                dev,
                connections: vec![],
                waiter: wait
            };
        }

        pub fn start_capture(&self) {
            let devs = Device::list().unwrap();
            let d = devs.get(self.dev).unwrap();
            let mut cap = d.clone().open().unwrap();

            println!(
                "{0: <12} | {1: <40} | {2: <40} | {3: <18} | {4: <15} | {5: <11}",
                "IP Protocol",
                "Destination IP",
                "Source IP",
                "Transport Protocol",
                "Destination Port",
                "Source Port"
            );
            
            let (sender_end, receiver_end) : (Sender<bool>, Receiver<bool>) = channel();
            
            let var= Arc::clone(&self.waiter);
            let t=thread::spawn(move || {
                let mut s= var.state.lock().unwrap();
                s.start_time = Instant::now();
                while ! s.pause {
                    let timer= s.time_interval.clone();
                    let res= var.cv.wait_timeout(s, Duration::from_secs(timer.to_bits())).unwrap();
                    if res.1.timed_out() {
                        sender_end.send(true).unwrap();
                        return ;
                    }
                    s = res.0;
                }
                s.pause_time=Instant::now();
                s.time_interval=(s.pause_time-s.start_time).as_secs_f64();
                sender_end.send(true).unwrap();
            });
            /*
            loop {
                let mut packet = cap.next().unwrap();
                match packet {

                }
            }*/

            while let Ok(packet) = cap.next() {
                if receiver_end.try_recv().is_ok(){
                    break;
                }
                match PacketHeaders::from_ethernet_slice(&packet) {
                    Err(value) => println!("Err {:?}", value),
                    Ok(value) => {
                        let mut temp_l3: u8 = 6;
                        let mut temp_ip_1  = "".to_string();
                        let mut temp_ip_2 = "".to_string();
                        let mut temp_l4: u8 = 0; 
                        let mut temp_port_1 = "".to_string();
                        let mut temp_port_2 = "".to_string();
                        
                        match value.ip.unwrap() {
                            IpHeader::Version4(h, _e) => {
                                temp_l3 = 4;
                                let dest = sprintf!(
                                    "%d.%d.%d.%d",
                                    h.destination[0],
                                    h.destination[1],
                                    h.destination[2],
                                    h.destination[3]
                                );
                                temp_ip_1 = dest.clone().unwrap();
                                let sour = sprintf!(
                                    "%d.%d.%d.%d",
                                    h.source[0],
                                    h.source[1],
                                    h.source[2],
                                    h.source[3]
                                );
                                temp_ip_2 = sour.clone().unwrap();
                                print!(
                                    "{0: <12} | {1:<40} | {2:<40} |",
                                    "IPv4",
                                    dest.unwrap(),
                                    sour.unwrap()
                                );
                            }
                            IpHeader::Version6(h, _e) => {
                                let dest = sprintf!("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x", 
                                    h.destination[0],h.destination[1],h.destination[2],h.destination[3],
                                    h.destination[4],h.destination[5],h.destination[6],h.destination[7],
                                    h.destination[8],h.destination[9],h.destination[10],h.destination[11],
                                    h.destination[12],h.destination[13],h.destination[14],h.destination[15]);
                                    temp_ip_1 = dest.clone().unwrap();
                                let sour = sprintf!("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                                    h.source[0],h.source[1],h.source[2],h.source[3],
                                    h.source[4],h.source[5],h.source[6],h.source[7],
                                    h.source[8],h.source[9],h.source[10],h.source[11],
                                    h.source[12],h.source[13],h.source[14],h.source[15]);
                                    temp_ip_2 = sour.clone().unwrap();
                                print!(
                                    "{0: <12} | {1:<40} | {2:<40} |",
                                    "IPv6",
                                    dest.unwrap(),
                                    sour.unwrap()
                                );
                            }
                        }
                        match value.transport.unwrap() {
                            
                            TransportHeader::Tcp(h) => {
                                print!(" {0: <18} |", "TCP");
                                print!(" {0: <16} |", h.destination_port);
                                println!(" {0: <11} |", h.source_port);
                                temp_port_1= h.destination_port.to_string();
                                temp_port_2 = h.source_port.to_string();
                            }
                            TransportHeader::Udp(h) => {
                                temp_l4 = 1;
                                print!(" {0: <18} |", "UDP");
                                print!(" {0: <16} |", h.destination_port);
                                println!(" {0: <11}", h.source_port);
                                temp_port_1= h.destination_port.to_string();
                                temp_port_2 = h.source_port.to_string();
                            }
                            _ => ()
                        }
                        //salviamo il vettore di connection
                        let temp_ts= sprintf!("%d.%d", packet.header.ts.tv_sec, packet.header.ts.tv_usec).unwrap();
                        let temp_connection = Connection::new(temp_l3,temp_ip_1,temp_ip_2,temp_l4,temp_port_1,temp_port_2,temp_ts,temp_ts,
                             packet.header.len);
                        let mut found = false;
                        for con in self.connections{
                            if con == temp_connection{
                                con.update(temp_ts, packet.header.len);
                                found == true;
                                break;
                            }
                        }
                        if !found {
                            self.connections.push(temp_connection);
                        }
                    }
                }
                //println!("{}.{}", packet.header.ts.tv_sec, packet.header.ts.tv_usec);
            }
            println!("Work done!");
            t.join().unwrap();
        }

        fn pause_capture(&self) {
            
        }

        //stampa temporanea su linea di comando
        pub fn print_connection(&self){
            println!(" ");
            println!(" ");
            println!(
                "{0: <12} | {1: <40} | {2: <40} | {3: <18} | {4: <15} | {5: <11} | {6: <17} | {7: <17} | {8: <10}",
                "IP Protocol",
                "Destination IP",
                "Source IP",
                "Transport Protocol",
                "Destination Port",
                "Source Port", 
                "Connection Start",
                "Connection End",
                "Data Size"
            );
            for con in self.connections {
                print!(" {0: <12} |", con.l3);
                print!(" {0: <40} |", con.ip_1);
                print!(" {0: <40} |", con.ip_2);

                print!(" {0: <18} |", con.l4);
                print!(" {0: <16} |", con.port_1);
                print!(" {0: <11} |", con.port_1);
                
                print!(" {0: <17} |", con.ts_start);
                print!(" {0: <17} |", con.ts_end);
                print!(" {0: <17} |", con.bytes);
               
            }
        }
    }
}
