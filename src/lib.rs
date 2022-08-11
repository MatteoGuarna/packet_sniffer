mod packet_sniffer {
    enum IpV {
        V4,
        V6
    }
    enum Transport {
        TCP,
        UDP
    }
    struct Connection {
        l3: IpV,
        ip_1: String,
        ip_2: String,
        l4: Transport,
        port_1: String,
        port_2: String,
        ts_start: String,
        ts_end: String
    }

    impl Connection{
        fn new (l3: u8, ip_1: String, ip_2: String, l4: u8, port_1: String, port_2: String, ts_start: String, ts_end: String) -> Self {
            let mut ip = IpV::V4;
            
            if l3 != 4 {
                ip=IpV::V6; 
            }
            
            let mut t=Transport::TCP;
            if l4 != 0 {
                t=Transport::UDP;
            }
             
            Self { l3: ip, ip_1, ip_2, l4: t, port_1, port_2, ts_start, ts_end }
        }
        

    }
}