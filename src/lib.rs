mod packet_sniffer {
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
        bytes: u64,
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
            bytes: u64,
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

        fn update(&mut self, new_ts_end: String, new_bytes: u64) {
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
}
