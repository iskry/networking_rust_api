use clap::{Command, Arg};
mod pcap;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = Command::new("Network Tool")
        .version("1.0")
        .author("Your Name <your_email@example.com>")
        .about("Captures network packets and manages iptables rules")
        .subcommand(
            Command::new("capture")
                .about("Captures network packets")
                .arg(Arg::new("interface")
                    .short('i')
                    .long("interface")
                    .takes_value(true)
                    .help("Specify the network interface to capture packets from"))
        )
        .subcommand(
            Command::new("list")
                .about("Lists iptables rules")
                .arg(Arg::new("table")
                    .help("Specifies the iptables table to list rules from")
                    .required(false)
                    .default_value("filter")
                    .index(1))
        )
        .get_matches();

    if let Some(capture_matches) = matches.subcommand_matches("capture") {
        let interface = capture_matches.value_of("interface");
        pcap::capture_packets(interface)?;
    }

    Ok(())
}
