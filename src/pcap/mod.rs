use pcap::{Capture, Device};
use pnet_packet::ethernet::{EtherTypes, EthernetPacket};
use pnet_packet::ipv4::Ipv4Packet;
use pnet_packet::tcp::TcpPacket;
use pnet_packet::udp::UdpPacket;
use pnet_packet::Packet;

pub fn capture_packets() -> Result<(), Box<dyn std::error::Error>> {
    let device = Device::lookup()?.unwrap();
    let mut cap = Capture::from_device(device)?
        .promisc(true)
        .snaplen(5000)
        .open()?;

    println!(
        "{:<20} {:<20} {:<17} {:<17} {:<9} {:<9}",
        "Src MAC", "Dst MAC", "Src IP", "Dst IP", "Src Port", "Dst Port"
    );
    println!("{:=<95}", "");

    while let Ok(packet) = cap.next_packet() {
        if let Some(ethernet) = EthernetPacket::new(packet.data) {
            let source_mac = ethernet.get_source().to_string();
            let destination_mac = ethernet.get_destination().to_string();

            match ethernet.get_ethertype() {
                EtherTypes::Ipv4 => {
                    if let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) {
                        let source_ip = ipv4.get_source().to_string();
                        let destination_ip = ipv4.get_destination().to_string();

                        let protocol = ipv4.get_next_level_protocol();
                        let (source_port, destination_port) = match protocol {
                            pnet_packet::ip::IpNextHeaderProtocols::Tcp => {
                                if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                                    (
                                        tcp.get_source().to_string(),
                                        tcp.get_destination().to_string(),
                                    )
                                } else {
                                    ("N/A".to_string(), "N/A".to_string())
                                }
                            }
                            pnet_packet::ip::IpNextHeaderProtocols::Udp => {
                                if let Some(udp) = UdpPacket::new(ipv4.payload()) {
                                    (
                                        udp.get_source().to_string(),
                                        udp.get_destination().to_string(),
                                    )
                                } else {
                                    ("N/A".to_string(), "N/A".to_string())
                                }
                            }
                            _ => ("N/A".to_string(), "N/A".to_string()),
                        };

                        println!(
                            "{:<20} {:<20} {:<17} {:<17} {:<9} {:<9}",
                            source_mac,
                            destination_mac,
                            source_ip,
                            destination_ip,
                            source_port,
                            destination_port
                        );
                    }
                }
                _ => println!("{:<20} {:<20} Non-IP packet", source_mac, destination_mac),
            }
        }
    }

    Ok(())
}

