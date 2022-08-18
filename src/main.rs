mod lib;
use crate::lib::packet_sniffer::Sniffer;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    
    if args.len() !=4  {
        println!("Too many arguments in command line");
        return ();
    } 

    let file_name = args[1].clone();
    
    let num : usize;
    match args[2].clone().parse() {
        Ok(n) => {
            num = n;
        },
        Err(_n) => {
            println!("Invalid argument (2)");
            return ;
        }
    }

    let time_interval : f64;
    match args[3].clone().parse() {
        Ok(t) => {
            time_interval = t;
        },
        Err(_t) => {
            println!("Invalid argument (3)");
            return ;
        }
    }
    
    let s = Sniffer::new(file_name, num, time_interval);
    match s {
        Ok(mut sniffer) => sniffer.start_capture(),
        Err(e) => println!("{}", e)
    }
    
}
