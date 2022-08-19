mod lib;
use crate::lib::packet_sniffer::Sniffer;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    
    if args.len() !=4 && args.len() != 5 {
        eprintln!("Wrong number of arguments in command line: expected -- \"filename\" \"number_of_network_device\" \"timer (seconds)\" \"filter (optional)\"");
        return ();
    } 

    let file_name = args[1].clone();
    
    let num : usize;
    match args[2].clone().parse() {
        Ok(n) => {
            num = n;
        },
        Err(_n) => {
            eprintln!("Invalid argument (2)");
            return ;
        }
    }

    let time_interval : f64;
    match args[3].clone().parse() {
        Ok(t) => {
            time_interval = t;
        },
        Err(_t) => {
            eprintln!("Invalid argument (3)");
            return ;
        }
    }
    let mut filter= String::new();

    if args.len() == 5 {
        filter = args[4].clone();
    }      
    
    //doppio match perché sia Sniffer::new che Sniffer::start_capture possono ritornare un errore 
    let s = Sniffer::new(file_name, num, time_interval,filter);
    match s {
        Ok(mut sniffer) => match sniffer.start_capture() {
            Err(e) => eprintln!("{}", e),
            _ => (),
        },
        Err(e) => eprintln!("{}", e)
    }
    
}
