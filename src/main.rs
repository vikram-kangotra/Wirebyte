use std::{
    net::{Ipv4Addr, Ipv6Addr}, sync::mpsc::{channel, Receiver, Sender}, thread
};

use egui::*;
use egui_extras::{Column, TableBuilder};
use pnet::{
    datalink::{self, NetworkInterface},
    packet::{arp::{ArpHardwareType, ArpHardwareTypes, ArpOperation, ArpOperations, ArpPacket}, ethernet::{EtherType, EtherTypes, EthernetPacket}, ip::{IpNextHeaderProtocol, IpNextHeaderProtocols}, ipv4::Ipv4Packet, ipv6::Ipv6Packet, tcp::TcpPacket, udp::UdpPacket, Packet},
    util::MacAddr,
};

enum Page {
    Home,
    Capture,
}

enum CaptureCommand {
    StartCapture,
    StopCapture,
}

#[allow(dead_code)]
struct Ipv4PacketView {
    pub version: u8,
    pub header_length: u8,
    pub dscp: u8,
    pub ecn: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags: u8,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub checksum: u16,
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    pub next_level_protocol: IpNextHeaderProtocol,
    next_level_protocol_view: NextLevelProtocolView,
    info: String,
}

pub struct Ipv6PacketView {
    pub version: u8,
    pub traffic_class: u8,
    pub flow_label: u32,
    pub payload_length: u16,
    pub next_header: IpNextHeaderProtocol,
    pub hop_limit: u8,
    pub source: Ipv6Addr,
    pub destination: Ipv6Addr,
    next_level_protocol_view: NextLevelProtocolView,
    pub info: String,
}

pub struct ArpPacketView {
    pub hardware_type: ArpHardwareType,
    pub protocol_type: EtherType,
    pub hw_addr_len: u8,
    pub proto_addr_len: u8,
    pub operation: ArpOperation,
    pub sender_hw_addr: MacAddr,
    pub sender_proto_addr: Ipv4Addr,
    pub target_hw_addr: MacAddr,
    pub target_proto_addr: Ipv4Addr,
    pub info: String,
}

enum EtherTypeView {
    Ipv4(Ipv4PacketView),
    Ipv6(Ipv6PacketView),
    Arp(ArpPacketView),
    Unknown,
}

impl EtherTypeView {
    #[allow(dead_code)]
    fn to_string(&self) -> String {
        match self {
            EtherTypeView::Ipv4(_) => "IPv4".to_owned(),
            EtherTypeView::Ipv6(_) => "IPv6".to_owned(),
            EtherTypeView::Arp(_) => "ARP".to_owned(),
            EtherTypeView::Unknown => "Unknown".to_owned(),
        }
    }

    fn source(&self) -> String {
        match self {
            EtherTypeView::Ipv4(ipv4_packet) => ipv4_packet.source.to_string(),
            EtherTypeView::Ipv6(ipv6_packet) => ipv6_packet.source.to_string(),
            EtherTypeView::Arp(arp_packet) => arp_packet.sender_proto_addr.to_string(),
            EtherTypeView::Unknown => "".to_owned(),
        }
    }
    

    fn destination(&self) -> String {
        match self {
            EtherTypeView::Ipv4(ipv4_packet) => ipv4_packet.destination.to_string(),
            EtherTypeView::Ipv6(ipv6_packet) => ipv6_packet.destination.to_string(),
            EtherTypeView::Arp(arp_packet) => arp_packet.target_proto_addr.to_string(),
            EtherTypeView::Unknown => "".to_owned(),
        }
    }

    fn protocol(&self) -> String {
        match self {
            EtherTypeView::Ipv4(ipv4_packet) => ipv4_packet.next_level_protocol.to_string().to_uppercase(),
            EtherTypeView::Ipv6(ipv6_packet) => ipv6_packet.next_header.to_string().to_uppercase(),
            EtherTypeView::Arp(_) => "ARP".to_owned(),
            EtherTypeView::Unknown => "Unknown".to_owned(),
        }
    }

    fn info(&self) -> String {
        match self {
            EtherTypeView::Ipv4(ipv4_packet) => self.prepare_info(&ipv4_packet.next_level_protocol_view),
            EtherTypeView::Ipv6(ipv6_packet) => self.prepare_info(&ipv6_packet.next_level_protocol_view),
            EtherTypeView::Arp(arp_packet) => arp_packet.info.to_string(),
            EtherTypeView::Unknown => "".to_owned(),
        } 
    }

    fn prepare_info(&self, protocol_view: &NextLevelProtocolView) -> String {
        match &protocol_view {
            NextLevelProtocolView::Tcp(tcp_packet) => {
                format!(
                    "{} -> {}, Seq: {}, Ack: {}, Len: {}",
                    tcp_packet.source_port,
                    tcp_packet.destination_port,
                    tcp_packet.sequence_number,
                    tcp_packet.acknowledgment_number,
                    tcp_packet.data_offset
                )
            }
            NextLevelProtocolView::Udp(udp_packet) => {
                format!(
                    "{} -> {}, Len: {}",
                    udp_packet.source_port,
                    udp_packet.destination_port,
                    udp_packet.length
                )
            }
            _ => "".to_owned(),
        }
    }

}

struct TcpPacketView {
    source_port: u16,
    destination_port: u16,
    sequence_number: u32,
    acknowledgment_number: u32,
    data_offset: u8,
    reserved: u8,
    flags: u8,
    window: u16,
    checksum: u16,
    urgent_pointer: u16,
}

struct UdpPacketView {
    source_port: u16,
    destination_port: u16,
    length: u16,
    checksum: u16,
}

enum NextLevelProtocolView {
    Tcp(TcpPacketView),
    Udp(UdpPacketView),
    Unknown,
}

struct EthernetPacketView {
    source: String,
    destination: String,
    ethertype: EtherTypeView,
}

struct PacketContent {
    ethernet_packet: EthernetPacketView,
    raw_packet: Vec<u8>,
}

struct MyApp {
    show_about: bool,
    started: bool,
    interfaces: Vec<NetworkInterface>,
    selected_interface: Option<usize>,
    selected_index: Option<usize>,
    current_page: Page,
    sender: Sender<Vec<u8>>,
    receiver: Receiver<Vec<u8>>,
    packet_list: Vec<PacketContent>,
    command_sender: Option<Sender<CaptureCommand>>,
    filter: String,
}

impl MyApp {
    fn new() -> Self {
        let (sender, receiver) = channel();

        Self {
            show_about: false,
            started: false,
            interfaces: datalink::interfaces(),
            selected_interface: None,
            selected_index: None,
            current_page: Page::Home,
            sender,
            receiver,
            packet_list: Vec::new(),
            command_sender: None,
            filter: "".to_owned(),
        }
    }

    fn start_capture(&mut self, interface: NetworkInterface, sender: Sender<Vec<u8>>) {
        let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
            Ok(datalink::Channel::Ethernet(_, rx)) => ((), rx),
            Ok(_) => panic!("Unhandled channel type"),
            Err(e) => panic!("Failed to create datalink channel: {}", e),
        };

        let (command_sender, command_receiver) = channel();
        self.command_sender = Some(command_sender);

        thread::spawn(move || {
            loop {
                if let Ok(command) = command_receiver.try_recv() {
                    match command {
                        CaptureCommand::StartCapture => continue,
                        CaptureCommand::StopCapture => break,
                    }
                }

                match rx.next() {
                    Ok(packet) => {
                        sender.send(packet.to_owned()).unwrap();
                    }
                    Err(e) => {
                        eprintln!("An error occurred while reading packet: {}", e);
                    }
                }
            }
        });
    }
    
    fn parse_next_level_protocol(&self, protocol: IpNextHeaderProtocol, payload: &[u8]) -> NextLevelProtocolView {
        match protocol {
            IpNextHeaderProtocols::Tcp => {
                let tcp_packet = TcpPacket::new(payload).unwrap();
                let tcp_packet_view = TcpPacketView {
                    source_port: tcp_packet.get_source(),
                    destination_port: tcp_packet.get_destination(),
                    sequence_number: tcp_packet.get_sequence(),
                    acknowledgment_number: tcp_packet.get_acknowledgement(),
                    data_offset: tcp_packet.get_data_offset(),
                    reserved: tcp_packet.get_reserved(),
                    flags: tcp_packet.get_flags(),
                    window: tcp_packet.get_window(),
                    checksum: tcp_packet.get_checksum(),
                    urgent_pointer: tcp_packet.get_urgent_ptr(),
                };
                NextLevelProtocolView::Tcp(tcp_packet_view)
            }
            IpNextHeaderProtocols::Udp => {
                let udp_packet = UdpPacket::new(payload).unwrap();
                let udp_packet_view = UdpPacketView {
                    source_port: udp_packet.get_source(),
                    destination_port: udp_packet.get_destination(),
                    length: udp_packet.get_length(),
                    checksum: udp_packet.get_checksum(),
                };
                NextLevelProtocolView::Udp(udp_packet_view)
            }
            _ => NextLevelProtocolView::Unknown,
        }
    }

    fn parse_packet(&self, raw_packet: &[u8]) -> PacketContent {

        let packet = EthernetPacket::new(raw_packet).unwrap();

        let ethernet_packet = EthernetPacketView {
            source: packet.get_source().to_string(),
            destination: packet.get_destination().to_string(),
            ethertype: match packet.get_ethertype() {
                EtherTypes::Ipv4 => {
                    let ipv4_payload = packet.payload();
                    let ipv4_packet = Ipv4Packet::new(ipv4_payload).unwrap();
                    let ipv4_packet_view = Ipv4PacketView {
                        version: ipv4_packet.get_version(),
                        header_length: ipv4_packet.get_header_length(),
                        dscp: ipv4_packet.get_dscp(),
                        ecn: ipv4_packet.get_ecn(),
                        total_length: ipv4_packet.get_total_length(),
                        identification: ipv4_packet.get_identification(),
                        flags: ipv4_packet.get_flags(),
                        fragment_offset: ipv4_packet.get_fragment_offset(),
                        ttl: ipv4_packet.get_ttl(),
                        checksum: ipv4_packet.get_checksum(),
                        source: ipv4_packet.get_source().into(),
                        destination: ipv4_packet.get_destination().into(),
                        next_level_protocol: ipv4_packet.get_next_level_protocol(),
                        next_level_protocol_view: self.parse_next_level_protocol(ipv4_packet.get_next_level_protocol(), ipv4_packet.payload()),
                        info: "".to_owned(),
                    };
                    EtherTypeView::Ipv4(ipv4_packet_view)
                }
                EtherTypes::Ipv6 => {
                    let ipv6_payload = packet.payload();
                    let ipv6_packet = Ipv6Packet::new(ipv6_payload).unwrap();
                    let ipv6_packet_view = Ipv6PacketView {
                        version: ipv6_packet.get_version(),
                        traffic_class: ipv6_packet.get_traffic_class(),
                        flow_label: ipv6_packet.get_flow_label(),
                        payload_length: ipv6_packet.get_payload_length(),
                        next_header: ipv6_packet.get_next_header(),
                        hop_limit: ipv6_packet.get_hop_limit(),
                        source: ipv6_packet.get_source().into(),
                        destination: ipv6_packet.get_destination().into(),
                        next_level_protocol_view: self.parse_next_level_protocol(ipv6_packet.get_next_header(), ipv6_packet.payload()),
                        info: "".to_owned(),
                    };
                    EtherTypeView::Ipv6(ipv6_packet_view)
                }
                EtherTypes::Arp => {
                    let arp_packet = ArpPacket::new(packet.payload()).unwrap();
                    let arp_packet_view = ArpPacketView {
                        hardware_type: arp_packet.get_hardware_type(),
                        protocol_type: arp_packet.get_protocol_type(),
                        hw_addr_len: arp_packet.get_hw_addr_len(),
                        proto_addr_len: arp_packet.get_proto_addr_len(),
                        operation: arp_packet.get_operation(),
                        sender_hw_addr: arp_packet.get_sender_hw_addr(),
                        sender_proto_addr: arp_packet.get_sender_proto_addr(),
                        target_hw_addr: arp_packet.get_target_hw_addr(),
                        target_proto_addr: arp_packet.get_target_proto_addr(),
                        info: match arp_packet.get_operation() {
                            ArpOperations::Request => {
                                format!(
                                    "Who has {}? Tell {}",
                                    arp_packet.get_target_proto_addr(),
                                    arp_packet.get_sender_proto_addr()
                                )
                            }
                            ArpOperations::Reply => {
                                format!(
                                    "{} is at {}",
                                    arp_packet.get_sender_proto_addr(),
                                    MacAddr::from(arp_packet.get_sender_hw_addr())
                                )
                            }
                            _ => "".to_owned(),
                        },
                    };
                    EtherTypeView::Arp(arp_packet_view)
                }
                _ => EtherTypeView::Unknown,
            },
        };

        PacketContent {
            ethernet_packet,
            raw_packet: raw_packet.to_owned(),
        }

    }

    fn show_menu(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("menu").show(ctx, |ui| {
            egui::menu::bar(ui, |ui| {
                ui.menu_button("File", |ui| {
                    if ui.button("Quit").clicked() {
                        ui.ctx().send_viewport_cmd(egui::viewport::ViewportCommand::Close);
                    }
                });
                ui.menu_button("Help", |ui| {
                    if ui.button("About").clicked() {
                        self.show_about = true;
                    }
                });
            });
        });
    }

    fn show_about_window(&mut self, ctx: &egui::Context) {
        egui::Window::new("About")
            .default_width(320.0)
            .default_height(480.0)
            .open(&mut self.show_about)
            .resizable(false)
            .collapsible(false)
            .show(ctx, |ui| {
                ui.label("WireByte");
                ui.label("Version: 0.1.0");
                ui.label("Author: Vikram Kangotra");
                ui.label("Description: A simple wireshark-like tool");
                ui.label("License: MIT");
            });
    }

    fn show_operations(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("operations").show(ctx, |ui| {
            egui::menu::bar(ui, |ui| {
                let start_image = egui::Image::new(include_image!("../assets/start.png"))
                    .fit_to_exact_size(Vec2::new(32.0, 32.0));
                let start_image = if self.started || self.selected_interface.is_none() {
                    start_image.tint(egui::Color32::from_rgb(150, 150, 150))
                } else {
                    start_image
                };
                let start_button = egui::widgets::Button::image(start_image);
                if ui.add(start_button).clicked() && self.selected_interface.is_some() {
                    self.started = true;
                    self.current_page = Page::Capture;
                    self.start_capture(
                        self.interfaces[self.selected_interface.unwrap()].clone(),
                        self.sender.clone(),
                    );
                    if let Some(command_sender) = &self.command_sender {
                        command_sender.send(CaptureCommand::StartCapture).unwrap();
                    }
                }

                let stop_image = egui::Image::new(include_image!("../assets/stop.png"))
                    .fit_to_exact_size(Vec2::new(32.0, 32.0));
                let stop_image = if self.started {
                    stop_image
                } else {
                    stop_image.tint(egui::Color32::from_rgb(150, 150, 150))
                };
                let stop_button = egui::widgets::Button::image(stop_image);
                if ui.add(stop_button).clicked() {
                    self.started = false;
                    if let Some(command_sender) = &self.command_sender {
                        command_sender.send(CaptureCommand::StopCapture).unwrap();
                    }
                }
            });
        });
    }

    fn show_interfaces(&mut self, ui: &mut Ui) {
        ui.vertical_centered(|ui| {
            ui.add_space(20.0);
            ui.heading("Available Interfaces");
            ui.add_space(20.0);

            ui.group(|ui| {
                ui.vertical_centered_justified(|ui| {
                    for (index, interface) in self.interfaces.iter().enumerate() {
                        let selected = self.selected_interface == Some(index);
                        if ui.add(SelectableLabel::new(selected, &interface.name)).clicked() {
                            self.selected_interface = Some(index);
                        }
                    }
                });
            });
        });
    }

    fn show_home_page(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            self.show_interfaces(ui);
        });
    }

    fn show_capture_page(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical(|ui| {
                egui::TopBottomPanel::top("filter")
                    .show(ctx, |ui| {
                        self.show_filter(ui);
                    });
                egui::TopBottomPanel::top("packet_list")
                    .resizable(false)
                    .min_height(ui.available_height() / 2.0)
                    .show(ctx, |ui| {
                        self.show_packet_list(ui);
                    });

                egui::TopBottomPanel::bottom("packet_details")
                    .resizable(false)
                    .min_height(ui.available_height() / 2.0)
                    .show(ctx, |ui| {
                        ui.columns(2, |uis| {
                            self.show_packet_details(&mut uis[0]);
                            self.show_packet_data(&mut uis[1]);
                        });
                    });
            });
        });
    }

    fn show_filter(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            ui.label("Filter:");
            ui.text_edit_singleline(&mut self.filter);
        });
    }

    fn show_packet_list(&mut self, ui: &mut Ui) {

        for packet in self.receiver.try_iter() {
            let packet_content = self.parse_packet(&packet);
            self.packet_list.push(packet_content);
        }


        let header_list = ["No.", "Source", "Destination", "Protocol", "Length", "Info"];
        TableBuilder::new(ui)
            .column(Column::auto())
            .columns(Column::remainder(), header_list.len() - 1)
            .sense(Sense::click())
            .header(20.0, |mut header| {
                for h in header_list {
                    header.col(|ui| {
                        ui.heading(h);
                    });
                }
            })
            .body(|mut body| {

                let packet_list = self.packet_list.iter().filter(|packet| {
                    let source_ip = packet.ethernet_packet.ethertype.source();
                    let destination_ip = packet.ethernet_packet.ethertype.destination();
                    let protocol = packet.ethernet_packet.ethertype.protocol();
                    let info = packet.ethernet_packet.ethertype.info();

                    let filter = self.filter.to_lowercase();

                    source_ip.to_lowercase().contains(&filter)
                        || destination_ip.to_lowercase().contains(&filter)
                        || protocol.to_lowercase().contains(&filter)
                        || info.to_lowercase().contains(&filter)
                });

                for (index, packet) in packet_list.enumerate() {
                    body.row(20., |mut row| {

                        let is_selected = self.selected_index == Some(index);

                        row.set_selected(is_selected);

                        row.col(|ui| {
                            ui.label(&(index + 1).to_string());
                        });
                        row.col(|ui| {
                            let source_ip = packet.ethernet_packet.ethertype.source();
                            ui.label(source_ip);
                        });
                        row.col(|ui| {
                            let destination_ip = packet.ethernet_packet.ethertype.destination();
                            ui.label(destination_ip);
                        });
                        row.col(|ui| {
                            let protocol = packet.ethernet_packet.ethertype.protocol();
                            ui.label(protocol);
                        });
                        row.col(|ui| {
                            let length = packet.raw_packet.len();
                            ui.label(length.to_string());
                        });
                        row.col(|ui| {
                            let info = packet.ethernet_packet.ethertype.info();
                            ui.label(info);
                        });

                        let response = row.response();

                        if response.clicked() {
                            self.selected_index = Some(row.index());
                        }

                    });
                }
            });
    }

    fn show_packet_details(&self, ui: &mut Ui) {
        ui.vertical(|ui| {
            ui.heading("Packet Details");
            
            let packet = match self.selected_index {
                Some(index) => &self.packet_list[index],
                None => return,
            };

            let frame_length = packet.raw_packet.len();
            let frame_length_bits = frame_length * 8;
            let interface = self.interfaces[self.selected_interface.unwrap()].clone();
            
            ScrollArea::both().show(ui, |ui| {

                let header = format!("Frame: {} bytes on wire ({} bits), {} bytes captured {} on interface {}", frame_length, frame_length_bits, frame_length, frame_length_bits, interface.name);

                CollapsingHeader::new(header).show(ui, |_ui| {});

                CollapsingHeader::new("Ethernet II").show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label("Destination:");
                        ui.label(packet.ethernet_packet.destination.clone());
                    });

                    ui.horizontal(|ui| {
                        ui.label("Source:");
                        ui.label(packet.ethernet_packet.source.clone());
                    });

                    ui.horizontal(|ui| {
                        ui.label("Type:");
                        ui.label(packet.ethernet_packet.ethertype.to_string());
                    });
                });

                match &packet.ethernet_packet.ethertype {
                    EtherTypeView::Ipv4(ipv4_packet) => {
                        self.show_ipv4_packet_details(ui, &ipv4_packet);
                        self.show_next_level_protocol_details(ui, &ipv4_packet.next_level_protocol_view);
                    }
                    EtherTypeView::Ipv6(ipv6_packet) => {
                        self.show_ipv6_packet_details(ui, &ipv6_packet);
                        self.show_next_level_protocol_details(ui, &ipv6_packet.next_level_protocol_view);
                    }
                    EtherTypeView::Arp(arp_packet) => self.show_arp_packet_details(ui, &arp_packet),
                    _ => {}
                }

            });
        });
    }

    fn show_packet_data(&self, ui: &mut Ui) {
        let packet = match self.selected_index {
            Some(index) => &self.packet_list[index],
            None => return,
        };

        let raw_packet = &packet.raw_packet;
        let total_width = ui.available_width();

        let first_column_width = total_width * 0.7;
        let second_column_width = total_width * 0.3;

        let mut hex_data = String::new();
        let mut ascii_data = String::new();

        for (index, byte) in raw_packet.iter().enumerate() {
            hex_data.push_str(&format!("{:02x} ", byte));
            ascii_data.push(if *byte >= 32 && *byte <= 126 {
                *byte as char
            } else {
                '.'
            });

            if (index + 1) % 8 == 0 {
                hex_data.push(' ');
            }

            if (index + 1) % 16 == 0 {
                hex_data.push('\n');
                ascii_data.push('\n');
            }
        }

        ScrollArea::both().show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.allocate_ui_with_layout(egui::Vec2::new(first_column_width, 0.0), egui::Layout::left_to_right(Align::LEFT), |ui| {
                    ui.monospace(&hex_data);
                });
                ui.allocate_ui_with_layout(egui::Vec2::new(second_column_width, 0.0), egui::Layout::left_to_right(Align::LEFT), |ui| {
                    ui.monospace(&ascii_data);
                });
            });
        });
    }

    fn show_ipv4_packet_details(&self, ui: &mut Ui, packet: &Ipv4PacketView) {

        let header = format!("Internet Protocol Version 4, Src: {}, Dst: {}", packet.source, packet.destination);

        CollapsingHeader::new(header).show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label("Version:");
                ui.label(packet.version.to_string());
            });

            ui.horizontal(|ui| {
                ui.label("Header Length:");
                ui.label(format!("{} bytes", packet.header_length));
            });

            ui.horizontal(|ui| {
                ui.label("Differentiated Services Field:");
                ui.label(format!("0x{:02x}", packet.dscp));
            });

            ui.horizontal(|ui| {
                ui.label("Total Length:");
                ui.label(packet.total_length.to_string());
            });

            ui.horizontal(|ui| {
                ui.label("Identification:");
                ui.label(packet.identification.to_string());
            });

            ui.horizontal(|ui| {
                ui.label("Flags:");
                ui.label(format!("0x{:02x}", packet.flags));
            });

            ui.horizontal(|ui| {
                ui.label("Fragment Offset:");
                ui.label(packet.fragment_offset.to_string());
            });

            ui.horizontal(|ui| {
                ui.label("Time to Live:");
                ui.label(packet.ttl.to_string());
            });

            ui.horizontal(|ui| {
                ui.label("Protocol:");
                ui.label(packet.next_level_protocol.to_string());
            });

            ui.horizontal(|ui| {
                ui.label("Header Checksum:");
                ui.label(format!("0x{:04x}", packet.checksum));
            });

            ui.horizontal(|ui| {
                ui.label("Source:");
                ui.label(packet.source.to_string());
            });

            ui.horizontal(|ui| {
                ui.label("Destination:");
                ui.label(packet.destination.to_string());
            });
        });
    }

    fn show_ipv6_packet_details(&self, ui: &mut Ui, packet: &Ipv6PacketView) {

        let header = format!("Internet Protocol Version 6, Src: {}, Dst: {}", packet.source, packet.destination);

        CollapsingHeader::new(header).show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label("Version:");
                ui.label(packet.version.to_string());
            });

            ui.horizontal(|ui| {
                ui.label("Traffic Class:");
                ui.label(format!("0x{:02x}", packet.traffic_class));
            });

            ui.horizontal(|ui| {
                ui.label("Flow Label:");
                ui.label(format!("0x{:08x}", packet.flow_label));
            });

            ui.horizontal(|ui| {
                ui.label("Payload Length:");
                ui.label(packet.payload_length.to_string());
            });

            ui.horizontal(|ui| {
                ui.label("Next Header:");
                ui.label(packet.next_header.to_string());
            });

            ui.horizontal(|ui| {
                ui.label("Hop Limit:");
                ui.label(packet.hop_limit.to_string());
            });

            ui.horizontal(|ui| {
                ui.label("Source:");
                ui.label(packet.source.to_string());
            });

            ui.horizontal(|ui| {
                ui.label("Destination:");
                ui.label(packet.destination.to_string());
            });
        });
    }

    fn show_arp_packet_details(&self, ui: &mut Ui, packet: &ArpPacketView) {

        let header = format!("Address Resolution Protocol ({})", match packet.operation {
            ArpOperations::Request => "Request",
            ArpOperations::Reply => "Reply",
            _ => "",
        });

        CollapsingHeader::new(header).show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label("Hardware type:");
                match packet.hardware_type {
                    ArpHardwareTypes::Ethernet => {
                        ui.label("Ethernet");
                    }
                    _ => {}
                }
            });

            ui.horizontal(|ui| {
                ui.label("Protocol type:");
                ui.label(packet.protocol_type.to_string());
            });

            ui.horizontal(|ui| {
                ui.label("Hardware address length:");
                ui.label(packet.hw_addr_len.to_string());
            });

            ui.horizontal(|ui| {
                ui.label("Protocol address length:");
                ui.label(packet.proto_addr_len.to_string());
            });

            ui.horizontal(|ui| {
                ui.label("Operation:");
                match packet.operation {
                    ArpOperations::Request => {
                        ui.label("Request");
                    }
                    ArpOperations::Reply => {
                        ui.label("Reply");
                    }
                    _ => {}
                }
            });

            ui.horizontal(|ui| {
                ui.label("Sender hardware address:");
                ui.label(packet.sender_hw_addr.to_string());
            });

            ui.horizontal(|ui| {
                ui.label("Sender protocol address:");
                ui.label(packet.sender_proto_addr.to_string());
            });

            ui.horizontal(|ui| {
                ui.label("Target hardware address:");
                ui.label(packet.target_hw_addr.to_string());
            });

            ui.horizontal(|ui| {
                ui.label("Target protocol address:");
                ui.label(packet.target_proto_addr.to_string());
            });
        });
    }

    fn show_next_level_protocol_details(&self, ui: &mut Ui, protocol: &NextLevelProtocolView) {
        match protocol {
            NextLevelProtocolView::Tcp(tcp_packet) => {
                self.show_tcp_packet_details(ui, tcp_packet);
            }
            NextLevelProtocolView::Udp(udp_packet) => {
                self.show_udp_packet_details(ui, udp_packet);
            }
            _ => {}
        }
    }

    fn show_tcp_packet_details(&self, ui: &mut Ui, packet: &TcpPacketView) {
        let header = format!("Transmission Control Protocol, Src Port: {}, Dst Port: {}", packet.source_port, packet.destination_port);

        CollapsingHeader::new(header).show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label("Source Port:");
                ui.label(packet.source_port.to_string());
            });

            ui.horizontal(|ui| {
                ui.label("Destination Port:");
                ui.label(packet.destination_port.to_string());
            });

            ui.horizontal(|ui| {
                ui.label("Sequence Number:");
                ui.label(packet.sequence_number.to_string());
            });

            ui.horizontal(|ui| {
                ui.label("Acknowledgment Number:");
                ui.label(packet.acknowledgment_number.to_string());
            });

            ui.horizontal(|ui| {
                ui.label("Data Offset:");
                ui.label(packet.data_offset.to_string());
            });

            ui.horizontal(|ui| {
                ui.label("Reserved:");
                ui.label(packet.reserved.to_string());
            });

            ui.horizontal(|ui| {
                ui.label("Flags:");
                ui.label(format!("0x{:02x}", packet.flags));
            });

            ui.horizontal(|ui| {
                ui.label("Window:");
                ui.label(packet.window.to_string());
            });

            ui.horizontal(|ui| {
                ui.label("Checksum:");
                ui.label(format!("0x{:04x}", packet.checksum));
            });

            ui.horizontal(|ui| {
                ui.label("Urgent Pointer:");
                ui.label(packet.urgent_pointer.to_string());
            });
        });
    }

    fn show_udp_packet_details(&self, ui: &mut Ui, packet: &UdpPacketView) {
        let header = format!("User Datagram Protocol, Src Port: {}, Dst Port: {}", packet.source_port, packet.destination_port);

        CollapsingHeader::new(header).show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label("Source Port:");
                ui.label(packet.source_port.to_string());
            });

            ui.horizontal(|ui| {
                ui.label("Destination Port:");
                ui.label(packet.destination_port.to_string());
            });

            ui.horizontal(|ui| {
                ui.label("Length:");
                ui.label(packet.length.to_string());
            });

            ui.horizontal(|ui| {
                ui.label("Checksum:");
                ui.label(format!("0x{:04x}", packet.checksum));
            });
        });
    }

}

impl eframe::App for MyApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui_extras::install_image_loaders(ctx);

        self.show_menu(ctx);
        self.show_operations(ctx);
        self.show_about_window(ctx);

        match self.current_page {
            Page::Home => self.show_home_page(ctx),
            Page::Capture => self.show_capture_page(ctx),
        }
    }
}

fn main() {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([1000.0, 600.0]),
        ..Default::default()
    };

    eframe::run_native(
        "WireByte",
        options,
        Box::new(|_cc| Box::new(MyApp::new())),
    )
    .unwrap();
}

