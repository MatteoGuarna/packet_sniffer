# packet sniffer

To obtain the documentation regarding this library please run the following instructions in this directory via command line:  
`cargo doc`  
`cargo doc --open`  

## Library dependencies
### __Windows__

Install [WinPcap](http://www.winpcap.org/install/default.htm).

Download the Wincap [Developer's Pack](https://www.winpcap.org/devel.htm).
Add the folder `/Lib` o `/Lib/x64` to the environment variable `LIB`.

### __Linux__

Install `libpcap-dev` with the command:
`sudo apt install libpcap-dev`

### __MacOS__

libpcap is already installed on MacOS.

## Library usage (lib.rs)

### PacketSniffer creation

```rust
let s = Sniffer::new(file, num, timer, filter).unwrap();

### starting capture

```rust
let c = sniffer.start_capture().unwrap();
```

### Error management

#### PacketSniffer creation

```rust
let s = Sniffer::new(file, num, timer, filter);
    match s {
        Ok(mut sniffer) => {/*No error*/},
        Err(SnifferError::DevicesListImpossibleToGet) => {/*error handler*/},
        Err(SnifferError::SnifferError::DevicesNotFound) => {/*error handler*/},
    }
```

#### PacketSniffer starting

```rust
match sniffer.start_capture() {
            Err(SnifferError::InvalidFilter) => {/*Error handler*/},
            Err(SnifferError::OpenErrorCapture) => {/*Error handler*/},
            _ => (),
        },
```

## How to start the example program (main.rs)

To be able to start the sniffer root permissions are required:

- Windows: Start the terminal / powershell as administrator
- Linux / macOS: use sudo

To find the interface IDs on Windows, run the `GETMAC / V` command.

From the root of the project you must first use `cargo build` to build the executable, which is
important because it is not possible to run the program with `cargo run` with root permissions.

Once the executable is genereted, it can be found inside `target/debug` with name `packet_sniffer`.

To run the executable via command line it is necessary to provide the following parameters:
`
./packet_sniffer -- --file 'file_name' --adapter 'device_number' --timer 'time(secs)' --filter 'filter' 
`

An example of running in Windows is:

```powershell
./target/debug/packet_sniffer --file "newfile.txt" --adapter 0 --timer 3.7 --filter "src port 443"
```

Once the execution is over or paused the sniffed connections are printed a file is generated inside the 'packet_sniffer' folder, unless a path is provided alongside the filename


### Keyboard commands

To pause and resume sniffing please type p (`pause`) and r (`resume`) during the execution. Use CTRL + C to end the program.


