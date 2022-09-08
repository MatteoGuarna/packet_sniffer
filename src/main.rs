mod lib;
use crate::lib::packet_sniffer::Sniffer;
use clap::Parser;

#[derive(Parser, Debug)]
struct Args {
    #[clap(short, long, value_parser, default_value_t = 0)]
    adapter: usize,
    #[clap(short, long, value_parser, default_value_t = 5.0)]
    time_interval: f64,
    #[clap(short, long, value_parser, default_value = "./results.txt")]
    file_name: String,
    #[clap(long, value_parser, default_value = "")]
    filter: String,
}

fn main() {
    let args: Args = Args::parse();  
    
    //doppio match perché sia Sniffer::new che Sniffer::start_capture possono ritornare un errore 
    let s = Sniffer::new(args.file_name, args.adapter, args.time_interval, args.filter);
    match s {
        Ok(mut sniffer) => match sniffer.start_capture() {
            Err(e) => eprintln!("{}", e),
            _ => println!("Work done!"),
        },
        Err(e) => eprintln!("{}", e)
    }
    
}
