pub mod packet_sniffer {
    //! packet_sniffer is a module cross-platform which allows to capture, analyze and filter packet 
    //! connections from a network device.
    //! # How to use packet_sniffer
    //! To create a new `packet_sniffer` object simply call the constructor
    //! ```
    //! let sniffer = Sniffer::new(file_name, network_device_number, time_interval, filter);
    //! ```
    //! #
    //! To start capturing the network traffic use the [`start_capture`] function
    //! ```
    //! sniffer.start_capture();
    //! ```
    //! The result of the capture is stored in your working folder
    //! ```
    //! ```
    //! It is possible to pause and resume the capture through the command line
    //! 
    use etherparse::{IpHeader, PacketHeaders, TransportHeader};
    use pcap::{Device,Capture};
    use sprintf::sprintf;
    use std::sync::{Condvar, Arc, Mutex};
    use std::time::{Duration, Instant};
    use std::thread;
    use std::sync::mpsc::{channel, Receiver, Sender};
    use std::fmt::{Display, Formatter, Result};
    use chrono::prelude::*;
    use std::fs::File;
    use std::io::{Write, stdin, stdout};

    /// This enum provides the different errors that can happen inside the sniffer mod
    /// 
    #[derive(Debug)]
    pub enum SnifferError {
        DevicesListImpossibleToGet,
        DeviceNotFound,
        InvalidFilter,
        OpenErrorCapture,
    }
    impl Display for SnifferError {
        fn fmt(&self, f: &mut Formatter) -> Result{
            match *self {
                SnifferError::DeviceNotFound => write!(f, "Device not found"),
                SnifferError::DevicesListImpossibleToGet => write!(f, "No devices available"),
                SnifferError::InvalidFilter => write!(f, "Invalid Filter: correct syntax is available at https://biot.com/capstats/bpf.html"),
                SnifferError::OpenErrorCapture => write!(f, "Impossible to open capture for the selected device "),
            }
        }
    }
    
    /// This enum provides the two version of an IP Packet
    #[derive(PartialEq,Clone, Debug)]
    enum IpV {
        V4,
        V6,
    }
    /// This enum provides the two type of the Trasport Layer
    #[derive(PartialEq,Clone, Debug)]
    enum Transport {
        TCP,
        UDP,
    }
    /// This struct identify a connection by IP addresses, ports and layer 3-4 protocols
    #[derive(Clone, Debug)]
    struct Connection {
        l3: IpV,
        ip_1: String,
        ip_2: String,
        l4: Transport,
        port_1: String,
        port_2: String,
        ts_start: DateTime<Local>,
        ts_end: DateTime<Local>,
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
                Transport::UDP => write!(f, "UDP"),
            }
        }
    }
    
    impl Connection {
        /// Create an istance of a Connection
        /// ## Parameters
        /// * `l3`: layer 3 protocol
        /// * `ip_1`: IP Address A
        /// * `ip_2`: IP Address B
        /// * `port_1`: Port A,
        /// * `port_2`: Port B,
        /// * `ts_start`: Initial Timestamp
        /// * `ts_end`: Final Timestamp
        /// * `bytes`: Cumulative bytes exchanged by the connection
        fn new(
            l3: u8,
            ip_1: String,
            ip_2: String,
            l4: u8,
            port_1: String,
            port_2: String,
            ts_start: DateTime<Local>,
            ts_end: DateTime<Local>,
            bytes: u32,
        ) -> Self {
            let mut ip = IpV::V4;

            if l3 != 4 {
                ip = IpV::V6;
            }

            let mut t = Transport::TCP;
            if l4 == 1 {
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

        /// Update an istance of a Connection
        /// ## Parameters
        /// * `new_ts_end`: New final Timestamp
        /// * `new_bytes`: New bytes to add in the Connection
        fn update(&mut self, new_ts_end: DateTime<Local>, new_bytes: u32){
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
    /// This struct defines the status of the Sniffer
    /// ## Properties
    /// * `time_interval`: Execute time of the Sniffer
    /// * `start_time`: Time the sniffer starts / resume to capture
    /// * `pause_time`: Time the sniffer pause the capturing
    /// * `pause`: Pause flag
    struct Status{
        time_interval: f64,
        start_time: Instant,
        pause_time: Instant,
        pause: bool,
    }
    
    /// This struct defines the synchronization variables used by the Sniffer
    /// ## Properties
    /// * `state`: Status of the Sniffer contained in a Mutex lock, even used with the cv
    /// * `cv`: Condition Variable
    struct Waiting{
        state: Mutex<Status>,
        cv: Condvar
    }
   
    /// This struct defines the Sniffer
    /// ## Properties
    /// * `file_name`: The name of the file (or the absolute or relative path) where the result of the capture is going to be printed
    /// * `dev`: Device identification number [an integer value ranging from 0 onwards which corresponde to a newtwork device interface]
    /// * `filter`: A filter (syntax is available at https://biot.com/capstats/bpf.html)
    /// * `connections`: A vector of Connections
    /// * `waiter`: Synchronization variable
    pub struct Sniffer{
        file_name: String,
        dev: String,
        filter: String,
        connections: Vec<Connection>,
        waiter: Arc<Waiting>
    }

    impl Sniffer {
        /// Creates an istance of Sniffer
        /// ## Parameters
        /// * `file_name`: The name of the file (or the absolute or relative path) where the result of the capture is going to be printed
        /// * `dev`: Device identification number [an integer value ranging from 0 onwards which corresponds to a network device interface]
        /// * `time_interval`: Sniffing Duration (secs)
        /// * `filter`: A filter (syntax is available at https://biot.com/capstats/bpf.html),
        /// #
        /// Please notice that the result of the capture is going stored in your working folder, unless a path is provided
        pub fn new(file_name: String, dev: usize, time_interval: f64, filter: String) -> std::result::Result<Self, SnifferError> {
            
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
            
            let devs = Device::list();
            let dev_name;
            match devs {
                Err(_e) => return Err(SnifferError::DevicesListImpossibleToGet),
                Ok(devs) => {
                    if devs.len() <= dev {
                        return Err(SnifferError::DeviceNotFound)
                    }
                    dev_name = devs.get(dev).unwrap().name.clone();
                }
            }

            return Ok(Sniffer {
                file_name,
                dev: dev_name,
                filter,
                connections: vec![],
                waiter: wait
            });
        }
        
    
    /// Returns nothing (unit) if the function succeds, otherwise returns a 'SnifferError' enum which details 
    /// the error encountered during the execution
    /// ```
    /// sniffer.start_capture();
    /// ```
    /// The result of the capture is stored in your working folder when the capture is over or paused
    /// ```
    /// ```
    /// It is possible to pause and resume the capture through the command line,
    /// by typing "p" and "r" respectively
        pub fn start_capture(& mut self) -> std::result::Result<(), SnifferError>{
            let mut cap = Capture::from_device(self.dev.as_str()).unwrap()
                        .promisc(true).timeout(500) //aggiunto timeout di 0.5s
                        .open().map_err(|_| SnifferError::OpenErrorCapture)?;
            cap.filter(&self.filter, true).map_err(|_| SnifferError::InvalidFilter)?;
            
            
            let (sender_end, receiver_end) : (Sender<String>, Receiver<String>) = channel();
            //cloning sync variable to be able to pass it to the sync thread
            let var= Arc::clone(&self.waiter);
            println!("> Starting capture from device: {} ...", self.dev); 
            println!("> Type \"p\" to pause ");
            //TIMER THREAD (2)
            //"move" allows to use all variables outside the newly created thread
            let t = thread::spawn(move || {
                let w = Arc::clone(&var);
                //USER COMMAND THREAD (3) 
                // - ttl depends on the father thread (this thread doesn't end on its own, stays in loop forever)
                thread::spawn(move || {
                    let mut cmd= String::new();
                    loop{
                        cmd.clear();
                        print!("> ");
                        stdout().flush().expect("Error flushing stdout buffer");
                        match stdin().read_line(&mut cmd){
                            Ok(_val) => (),
                            Err(e) => {eprintln!("{}", e); continue}
                        }
                        let r= cmd.trim();
                        match r {
                            "p" => {
                                let mut res= w.state.lock().unwrap();
                                if res.pause {drop(res); continue;}
                                res.pause = true;
                                w.cv.notify_all();
                                drop(res);

                            },
                            "r" => {
                                let mut res= w.state.lock().unwrap();
                                if !res.pause {drop(res); continue;}
                                res.pause = false;
                                w.cv.notify_all();
                                drop(res);
                            }
                             _ => ()
                        }
                    }

                });
                //back to timer thread
                loop {
                    let mut s= var.state.lock().unwrap();
                    while s.pause {
                        s = var.cv.wait(s).unwrap();
                    }
                    sender_end.send(String::from("resume")).unwrap();
                    s.start_time = Instant::now();
                    
                    //RUNNING
                    while ! s.pause {
                        let timer= s.time_interval.clone();
                        //inside function "wait" lock is freed, and is taken back when wait is over
                        //in fact the lock "s" is passed to the function
                        let res= var.cv.wait_timeout(s, Duration::from_secs(timer as u64)).unwrap();
                        if res.1.timed_out() {
                            sender_end.send(String::from("timeout")).unwrap();
                            return ;
                        }
                        s = res.0; //avoids res consumption when while reaches the end
                    }
                    
                    //PAUSE
                    //code reached only when mutex is in pause status (sniffer is paused)
                    s.pause_time=Instant::now();
                    s.time_interval -= (s.pause_time-s.start_time).as_secs_f64();
                    println!("Time left: {:.1} secs", s.time_interval);
                
                    sender_end.send(String::from("pause")).unwrap();
                }
            });
            
            //creato questo loop perché il while Ok(cap.next()) usciva dal ciclo quando trovava un errore in pacchetto e non permetteva la synch
            loop {
                
                match receiver_end.try_recv() {
                    Ok(val) => {
                        match val.as_str(){
                            "timeout" => break,
                            "pause" => {
                                self.print_connection();
                                print!("> {} printed, work paused!\n> Type \"r\" to resume\n> ", self.file_name);
                                stdout().flush().unwrap();
                                let r = receiver_end.recv().unwrap();
                                match r.as_str(){
                                    "resume" => {
                                            print!("RESUME!\n> Type \"p\" to pause\n> ");
                                            stdout().flush().unwrap();
                                    }
                                    _ => ()
                                }
                            },
                            _ => ()
                        }

                    },
                    _ => ()
                }

                match cap.next() {
                    Ok(packet) => {
                        match PacketHeaders::from_ethernet_slice(&packet) {
                            Err(value) => println!("Err {:?}", value),
                            Ok(value) => {
                                let mut temp_l3: u8 = 6;
                                #[allow(unused_assignments)]
                                let mut temp_ip_1  = "".to_string();
                                #[allow(unused_assignments)]
                                let mut temp_ip_2 = "".to_string();
                                let mut temp_l4: u8 = 0; 
                                #[allow(unused_assignments)]
                                let mut temp_port_1 = "".to_string();
                                #[allow(unused_assignments)]
                                let mut temp_port_2 = "".to_string();
                                if value.ip.is_none() { continue; }
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
                                    },
                                }
                                if value.transport.is_none(){ continue; }
                                match value.transport.unwrap() {
                                    TransportHeader::Tcp(h) => {
                                        temp_port_1= h.destination_port.to_string();
                                        temp_port_2 = h.source_port.to_string();
                                    }
                                    TransportHeader::Udp(h) => {
                                        temp_l4 = 1;
                                        temp_port_1= h.destination_port.to_string();
                                        temp_port_2 = h.source_port.to_string();
                                    }
                                    _ => continue
                                }
                                //salviamo il vettore di connection
                                let temp_ts= DateTime::from_local(NaiveDateTime::from_timestamp(packet.header.ts.tv_sec as i64, packet.header.ts.tv_usec as u32), *(chrono::Local::now().offset()))+*(chrono::Local::now().offset());
                    
                                let temp_connection = Connection::new(temp_l3,temp_ip_1,temp_ip_2,temp_l4,temp_port_1,temp_port_2,temp_ts.clone(),temp_ts.clone(),
                                    packet.header.len);

                                let mut found = false;
                                let mut i: usize=0;
                                while i < self.connections.len() {
                                    if self.connections[i] == temp_connection{
                                        self.connections[i].update(temp_ts, packet.header.len);
                                        found = true;
                                        break;
                                    }
                                    i+=1;
                                }
                                
                                if !found {
                                    self.connections.push(temp_connection);
                                }
                            }
                        }
                    },
                    _ => (),
                }
            }
            println!("Work done!");
            t.join().unwrap();
            self.print_connection();
            return Ok(());
        }

        
        /// print_connection creates o overwrite a file writing the result of sniffing
        pub fn print_connection(&self){
            let mut writer= File::create(self.file_name.clone()).unwrap();

         
            let mut i = 1;
            writeln!(writer, " WIRECATFISH packet capture\n").unwrap();
            writeln!(writer, "| N°   | {0: <11} | {1: <40} | {2: <40} | {3: <18} | {4: <15} | {5: <11} | {6: <19} | {7: <19} | {8: <24} |",
            "IP Protocol",
            "Address A",
            "Address B",
            "Transport Protocol",
            "Port A",
            "Port B", 
            "Connection Start",
            "Connection End ",
            "Data Trasmitted (Bytes)").unwrap();

            for con in self.connections.clone() {
                writeln!(writer, "| {0: <4} | {1}        | {2: <40} | {3: <40} | {4}                | {5: <15} | {6: <11} | {7: <19} | {8: <19} | {9: <24} |",
                i,
                con.l3,
                con.ip_1,
                con.ip_2,
                con.l4,
                con.port_1,
                con.port_2, 
                con.ts_start.format("%Y/%m/%d %H:%M:%S"),
                con.ts_end.format("%Y/%m/%d %H:%M:%S"),
                con.bytes
            ).unwrap();
            i+=1;
            }
        }
    }
}
