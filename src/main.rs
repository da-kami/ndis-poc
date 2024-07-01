/// Note by Daniel:
/// Example base on: https://github.com/wiresock/ndisapi-rs/blob/main/examples/filter.rs

/// This example demonstrates the basic usage of the `set_packet_filter_table` API, showcasing different filter scenarios:
///
/// 1. Redirect only DNS packets for user mode processing.
/// 2. Redirect only HTTP (TCP port 80) packets for user mode processing.
use clap::Parser;
use ndisapi::{
    DataLinkLayerFilter, DirectionFlags, EthRequest, EthRequestMut, FilterFlags, FilterLayerFlags,
    IntermediateBuffer, IpAddressV4, IpAddressV6, IpV4Filter, IpV4FilterFlags, IpV6Filter,
    IpV6FilterFlags, Ndisapi, NetworkLayerFilter, NetworkLayerFilterUnion, PortRange, StaticFilter,
    StaticFilterTable, TcpUdpFilter, TcpUdpFilterFlags, TransportLayerFilter,
    TransportLayerFilterUnion, FILTER_PACKET_PASS, FILTER_PACKET_REDIRECT, IPV4, IPV6, TCPUDP,
};
use smoltcp::wire::{EthernetFrame, EthernetProtocol, IpProtocol, Ipv4Packet, TcpPacket};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use windows::{
    core::Result,
    Win32::Foundation::{CloseHandle, HANDLE},
    Win32::System::Threading::{CreateEventW, ResetEvent, SetEvent, WaitForSingleObject},
};

#[derive(Parser)]
struct Cli {
    /// Network interface index (please use listadapters example to determine the right one)
    #[clap(short, long)]
    interface_index: usize,
}

// Address Resolution packet

const IPPROTO_TCP: u8 = 6;

const HTTP_PORT: u16 = 80;

/// Sets up a packet filter table for HTTP packets over IPv4 and IPv6.
///
/// This function configures a packet filter table with five filters:
///
/// 1. Outgoing HTTP requests filter (IPv4): This filter redirects outgoing TCP packets with destination port 80 (HTTP) for processing in user mode. It applies to all network adapters.
///
/// 2. Incoming HTTP responses filter (IPv4): This filter redirects incoming TCP packets with source port 80 (HTTP) for processing in user mode. It applies to all network adapters.
///
/// 3. Outgoing HTTP requests filter (IPv6): This filter redirects outgoing TCP packets with destination port 80 (HTTP) for processing in user mode. It applies to all network adapters.
///
/// 4. Incoming HTTP responses filter (IPv6): This filter redirects incoming TCP packets with source port 80 (HTTP) for processing in user mode. It applies to all network adapters.
///
/// 5. Default pass filter: This filter passes all packets that are not matched by the previous filters without processing in user mode. It applies to all network adapters.
///
/// After setting up the filter table, this function applies it to the network interface using the `set_packet_filter_table` method of the `Ndisapi` object.
///
/// # Arguments
///
/// * `ndisapi` - A reference to the `Ndisapi` object that represents the network interface.
///
/// # Returns
///
/// This function returns a `Result` that indicates whether the operation succeeded or failed. If the operation succeeded, the `Result` contains `()`. If the operation failed, the `Result` contains an error.
///
/// # Examples
///
/// ------------------------
///
/// Notes by Daniel:
///
/// Modified to only redirect the outgoing traffic.
/// We then modify the packet destination address and port to point towards the proxy.
fn load_http_ipv4v6_filters(ndisapi: &Ndisapi) -> Result<()> {
    let filter_table = StaticFilterTable::<5>::from_filters([
        // 1. Outgoing HTTP requests filter: REDIRECT OUT TCP packets with destination PORT 80 IPv4
        StaticFilter::new(
            0, // applied to all adapters
            DirectionFlags::PACKET_FLAG_ON_SEND,
            FILTER_PACKET_REDIRECT,
            FilterLayerFlags::NETWORK_LAYER_VALID | FilterLayerFlags::TRANSPORT_LAYER_VALID,
            DataLinkLayerFilter::default(),
            NetworkLayerFilter::new(
                IPV4,
                NetworkLayerFilterUnion {
                    ipv4: IpV4Filter::new(
                        IpV4FilterFlags::IP_V4_FILTER_PROTOCOL,
                        IpAddressV4::default(),
                        IpAddressV4::default(),
                        IPPROTO_TCP,
                    ),
                },
            ),
            TransportLayerFilter::new(
                TCPUDP,
                TransportLayerFilterUnion {
                    tcp_udp: TcpUdpFilter::new(
                        TcpUdpFilterFlags::TCPUDP_DEST_PORT,
                        PortRange::default(),
                        PortRange::new(HTTP_PORT, 443),
                        0u8,
                    ),
                },
            ),
        ),
        // 2. Incoming HTTP responses filter: PASS IN TCP packets with source PORT 80 IPv4
        StaticFilter::new(
            0, // applied to all adapters
            DirectionFlags::PACKET_FLAG_ON_RECEIVE,
            FILTER_PACKET_PASS,
            FilterLayerFlags::NETWORK_LAYER_VALID | FilterLayerFlags::TRANSPORT_LAYER_VALID,
            DataLinkLayerFilter::default(),
            NetworkLayerFilter::new(
                IPV4,
                NetworkLayerFilterUnion {
                    ipv4: IpV4Filter::new(
                        IpV4FilterFlags::IP_V4_FILTER_PROTOCOL,
                        IpAddressV4::default(),
                        IpAddressV4::default(),
                        IPPROTO_TCP,
                    ),
                },
            ),
            TransportLayerFilter::new(
                TCPUDP,
                TransportLayerFilterUnion {
                    tcp_udp: TcpUdpFilter::new(
                        TcpUdpFilterFlags::TCPUDP_SRC_PORT,
                        PortRange::new(HTTP_PORT, 443),
                        PortRange::default(),
                        0u8,
                    ),
                },
            ),
        ),
        // 3. Outgoing HTTP requests filter: REDIRECT OUT TCP packets with destination PORT 80 IPv6
        StaticFilter::new(
            0, // applied to all adapters
            DirectionFlags::PACKET_FLAG_ON_SEND,
            FILTER_PACKET_REDIRECT,
            FilterLayerFlags::NETWORK_LAYER_VALID | FilterLayerFlags::TRANSPORT_LAYER_VALID,
            DataLinkLayerFilter::default(),
            NetworkLayerFilter::new(
                IPV6,
                NetworkLayerFilterUnion {
                    ipv6: IpV6Filter::new(
                        IpV6FilterFlags::IP_V6_FILTER_PROTOCOL,
                        IpAddressV6::default(),
                        IpAddressV6::default(),
                        IPPROTO_TCP,
                    ),
                },
            ),
            TransportLayerFilter::new(
                TCPUDP,
                TransportLayerFilterUnion {
                    tcp_udp: TcpUdpFilter::new(
                        TcpUdpFilterFlags::TCPUDP_DEST_PORT,
                        PortRange::default(),
                        PortRange::new(HTTP_PORT, 443),
                        0u8,
                    ),
                },
            ),
        ),
        // 4. Incoming HTTP responses filter: PASS IN TCP packets with source PORT 80 IPv6
        StaticFilter::new(
            0, // applied to all adapters
            DirectionFlags::PACKET_FLAG_ON_RECEIVE,
            FILTER_PACKET_PASS,
            FilterLayerFlags::NETWORK_LAYER_VALID | FilterLayerFlags::TRANSPORT_LAYER_VALID,
            DataLinkLayerFilter::default(),
            NetworkLayerFilter::new(
                IPV6,
                NetworkLayerFilterUnion {
                    ipv6: IpV6Filter::new(
                        IpV6FilterFlags::IP_V6_FILTER_PROTOCOL,
                        IpAddressV6::default(),
                        IpAddressV6::default(),
                        IPPROTO_TCP,
                    ),
                },
            ),
            TransportLayerFilter::new(
                TCPUDP,
                TransportLayerFilterUnion {
                    tcp_udp: TcpUdpFilter::new(
                        TcpUdpFilterFlags::TCPUDP_SRC_PORT,
                        PortRange::new(HTTP_PORT, 443),
                        PortRange::default(),
                        0u8,
                    ),
                },
            ),
        ),
        // 5. Drop all packets (skipped by previous filters) without processing in user mode
        StaticFilter::new(
            0, // applied to all adapters
            DirectionFlags::PACKET_FLAG_ON_RECEIVE | DirectionFlags::PACKET_FLAG_ON_SEND,
            FILTER_PACKET_PASS,
            FilterLayerFlags::empty(),
            DataLinkLayerFilter::default(),
            NetworkLayerFilter::default(),
            TransportLayerFilter::default(),
        ),
    ]);

    ndisapi.set_packet_filter_table(&filter_table)
}

/// Entry point of the application.
///
/// This function parses the command line arguments, initializes the Ndisapi driver, sets up the packet filter table based on the selected filter set, and starts the packet processing loop.
///
/// The packet processing loop reads packets from the network interface, prints some information about each packet, and then re-injects the packets back into the network stack.
///
/// The loop continues until the user presses Ctrl-C.
///
/// # Arguments
///
/// None.
///
/// # Returns
///
/// This function returns a `Result` that indicates whether the operation succeeded or failed. If the operation succeeded, the `Result` contains `()`. If the operation failed, the `Result` contains an error.
///
/// # Examples
///
///
fn main() -> Result<()> {
    // Parse command line arguments
    let Cli {
        mut interface_index,
    } = Cli::parse();

    // Adjust the interface index to be zero-based
    interface_index -= 1;

    // Initialize the Ndisapi driver
    let driver =
        Ndisapi::new("NDISRD").expect("WinpkFilter driver is not installed or failed to load!");

    // Print the version of the WinpkFilter driver
    println!(
        "Detected Windows Packet Filter version {}",
        driver.get_version()?
    );

    // Get the list of network interfaces that are bound to TCP/IP
    let adapters = driver.get_tcpip_bound_adapters_info()?;

    // Check if the selected interface index is valid
    if interface_index + 1 > adapters.len() {
        panic!("Interface index is beyond the number of available interfaces");
    }

    // Print the name of the selected network interface
    println!("Using interface {}s", adapters[interface_index].get_name());

    load_http_ipv4v6_filters(&driver)?;

    // Create a Win32 event for packet arrival notification
    let event: HANDLE;
    unsafe {
        event = CreateEventW(None, true, false, None)?;
    }

    // Set up a Ctrl-C handler to terminate the packet processing loop
    let terminate: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
    let ctrlc_pressed = terminate.clone();
    ctrlc::set_handler(move || {
        println!("Ctrl-C was pressed. Terminating...");
        // Set the atomic flag to exit the loop
        ctrlc_pressed.store(true, Ordering::SeqCst);
        // Signal the event to release the loop if there are no packets in the queue
        let _ = unsafe { SetEvent(event) };
    })
    .expect("Error setting Ctrl-C handler");

    // Set the event within the driver for packet arrival notification
    driver.set_packet_event(adapters[interface_index].get_handle(), event)?;

    // Put the network interface into tunnel mode
    driver.set_adapter_mode(
        adapters[interface_index].get_handle(),
        FilterFlags::MSTCP_FLAG_SENT_RECEIVE_TUNNEL,
    )?;

    // Allocate a single IntermediateBuffer on the stack for packet reading
    let mut packet = IntermediateBuffer::default();

    // Start the packet processing loop
    while !terminate.load(Ordering::SeqCst) {
        // Wait for a packet to arrive
        unsafe {
            WaitForSingleObject(event, u32::MAX);
        }
        loop {
            // Initialize an EthRequestMut to pass to the driver API
            let mut read_request = EthRequestMut::new(adapters[interface_index].get_handle());

            // Set the packet buffer
            read_request.set_packet(&mut packet);

            // Read a packet from the network interface
            if driver.read_packet(&mut read_request).ok().is_none() {
                // No more packets in the queue, break the loop
                break;
            }

            // Get the direction of the packet
            let direction_flags = packet.get_device_flags();

            // Print packet information
            if direction_flags == DirectionFlags::PACKET_FLAG_ON_SEND {
                println!("\nMSTCP --> Interface ({} bytes)\n", packet.get_length());
            } else {
                println!("\nInterface --> MSTCP ({} bytes)\n", packet.get_length());
            }

            // Print some information about the packet
            modify_packet(&mut packet);

            // Initialize an EthRequest to pass to the driver API
            let mut write_request = EthRequest::new(adapters[interface_index].get_handle());

            // Set the packet buffer
            write_request.set_packet(&packet);

            // Re-inject the packet back into the network stack
            if direction_flags == DirectionFlags::PACKET_FLAG_ON_SEND {
                // Send the packet to the network interface
                match driver.send_packet_to_adapter(&write_request) {
                    Ok(_) => {}
                    Err(err) => println!("Error sending packet to adapter. Error code = {err}"),
                };
            } else {
                // Send the packet to the TCP/IP stack
                match driver.send_packet_to_mstcp(&write_request) {
                    Ok(_) => {}
                    Err(err) => println!("Error sending packet to mstcp. Error code = {err}"),
                }
            }
        }

        // Reset the event to continue waiting for packets to arrive
        let _ = unsafe { ResetEvent(event) };
    }

    // Put the network interface back into default mode
    driver.set_adapter_mode(
        adapters[interface_index].get_handle(),
        FilterFlags::default(),
    )?;

    // Close the event handle
    let _ = unsafe { CloseHandle(event) };

    // Return success
    Ok(())
}

/// Print detailed information about a network packet.
///
/// This function takes an `IntermediateBuffer` containing a network packet and prints various
/// details about the packet, such as Ethernet, IPv4, IPv6, ICMPv4, ICMPv6, UDP, and TCP information.
///
/// # Arguments
///
/// * `packet` - A reference to an `IntermediateBuffer` containing the network packet.
///
/// # Examples
///
/// ```no_run
/// let packet: IntermediateBuffer = ...;
/// print_packet_info(&packet);
/// ```
fn modify_packet(packet: &mut IntermediateBuffer) {
    let mut eth_hdr = EthernetFrame::new_unchecked(packet.get_data_mut());
    match eth_hdr.ethertype() {
        EthernetProtocol::Ipv4 => {
            let mut ipv4_packet = Ipv4Packet::new_unchecked(eth_hdr.payload_mut());

            println!(
                "  Ipv4 {:?} => {:?}",
                ipv4_packet.src_addr(),
                ipv4_packet.dst_addr()
            );

            // re-route to localhost
            ipv4_packet.set_dst_addr(smoltcp::wire::Ipv4Address([127, 0, 0, 1]));

            let src_addr = ipv4_packet.src_addr();
            let dst_addr = ipv4_packet.dst_addr();

            // fill checksum after modifying the address
            ipv4_packet.fill_checksum();

            println!("  Ipv4 after modification {:?} => {:?}", src_addr, dst_addr);

            match ipv4_packet.next_header() {
                IpProtocol::Tcp => {
                    let mut tcp_packet = TcpPacket::new_unchecked(ipv4_packet.payload_mut());
                    println!(
                        "   TCP {:?} -> {:?}",
                        tcp_packet.src_port(),
                        tcp_packet.dst_port()
                    );

                    // reroute to port 18081
                    tcp_packet.set_dst_port(18081);
                    // fill checksum because address changed
                    tcp_packet.fill_checksum(&src_addr.into_address(), &dst_addr.into_address());

                    println!(
                        "   TCP port after modification {:?} -> {:?}",
                        tcp_packet.src_port(),
                        tcp_packet.dst_port()
                    );
                }
                _ => {
                    println!("don't really care about this packet: {:?}", ipv4_packet);
                }
            }
        }
        EthernetProtocol::Ipv6 => {
            println!("Handle IPv6 later");
        }
        _ => {
            println!("Don't care about this Ethernet packet: {:?}", eth_hdr);
        }
    }
}
