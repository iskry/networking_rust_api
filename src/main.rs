mod pcap;

use clap::{Arg, ArgAction, Command};
use iptables::IPTables;
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = Command::new("IPTABLES Manager")
        .version("0.1.0")
        .author("Your Name")
        .about("Manages iptables rules and captures network traffic")
        .subcommand(
            Command::new("list").about("Lists iptables rules").arg(
                Arg::new("table")
                    // .short('t')
                    // .long("table")
                    .required(true)
                    .index(1)
                    // .action(ArgAction::Set)
                    .help("The iptables table to list rules from"),
            ),
        )
        .subcommand(Command::new("capture").about("Captures network packets"))
        .get_matches();

    if let Some(matches) = matches.subcommand_matches("list") {
        let table = matches
            .get_one::<String>("table")
            .map(|s| s.as_str())
            .unwrap_or("filter");
        list_rules(table)?;
    }
    if matches.subcommand_matches("capture").is_some() {
        pcap::capture_packets()?;
    }

    Ok(())
}

fn list_rules(table: &str) -> Result<(), Box<dyn std::error::Error>> {
    let ipt = iptables::new(false).unwrap();

    let rules = ipt.list(table, "INPUT")?; // Adjust "INPUT" to the chain you're interested in
    for rule in rules {
        println!("{}", rule);
    }
    Ok(())
}
