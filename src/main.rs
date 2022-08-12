mod lib;
use crate::lib::packet_sniffer::Sniffer;

fn main() {
    let file_name=String::from("file_prova.txt");
    let num: usize = 1;
    let time_interval: u64 = 3;
    let s = Sniffer::new(file_name, num, time_interval);
    s.start_capture();
    s.print_connection();
}
