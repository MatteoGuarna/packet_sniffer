mod lib;
use crate::lib::packet_sniffer::Sniffer;

fn main() {
    let file_name=String::from("file_prova.txt");
    let num: usize = 3;
    let time_interval: f64 = 1.0;
    let mut s = Sniffer::new(file_name, num, time_interval);
    s.start_capture();
    s.print_connection();
}
