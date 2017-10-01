use options::{DhcpOption};
use options::DhcpOption::*;
use { Result };
use nom::{be_u8, be_u16, be_u32, be_i32, IResult, sized_buffer};
use std::borrow::{ToOwned};
use std::str;
use std::convert::{From};
use std::net::{IpAddr, Ipv4Addr};
use num::{FromPrimitive};
use options::option82::relay_agent_information_option_rfc3046;

pub fn parse(bytes: &[u8]) -> Result<Vec<DhcpOption>> {
    let mut vec = Vec::new();
    if bytes.len() > 0 {
        let mut remaining = Some(bytes);
        while let Some(unparsed) = remaining {
            // Do some basic sanity checks before actually parsing
            match unparsed.len() {
                0 => {
                    // Shouldn't get here, but just in case
                    remaining = None;
                    continue;
                },
                1 => {
                    // If there's only a single byte left
                    // make sure it's a valid single byte option
                    if unparsed[0] != 0u8 && unparsed[0] != 255u8 {
                        remaining = None;
                        continue;
                    }
                },
                // TODO: Any 2 byte options?
                _ => {
                    // If there are several bytes left and the next byte
                    // is not a single byte option
                    if unparsed[0] != 0u8 && unparsed[0] != 255u8 {
                        // Assume it's an option in the standard format:
                        // [Option Number Field] (1 byte) [Length Field] (1 byte) [Rest of option...]
                        // and calculte the option length as:
                        // opt_num_field (1 byte) + opt_len_field (1 byte) + value_in_opt_len_field
                        let option_length: usize = 2 + (unparsed[1] as usize);
                        // Sanity check the option is actually within bounds of
                        // remaining byte array
                        if option_length > unparsed.len() {
                            remaining = None;
                            continue;
                        }
                    }
                },
            }

            // If an option was successfully parsed
            if let IResult::Done(rest, opt) = dhcp_option(unparsed) {
                // If this is the end of options
                if opt == DhcpOption::End || rest.len() == 0 {
                    remaining = None;
                } else {
                    remaining = Some(rest);
                }
                vec.push(opt);
            } else {
                // It's either an:
                //   • error/invalid option
                //   • option we don't know
                // In either case, assume initially that there's nothing left we can parse
                remaining = None;

                // See if we can recover gracefully and continue parsing any remaining options
                if unparsed.len() > 2 {
                    // Skip this option but assume it's an option in the
                    // standard format & parse the remaining options if possible
                    let start_of_next_option: usize = 2 + (unparsed[1] as usize);

                    // Sanity check the start of (any) remaning options are within
                    // the bounds of remaining byte array
                    if unparsed.len() > start_of_next_option {
                        remaining = Some(&unparsed[start_of_next_option..]);
                    }
                }
            }
        }
    }
    Ok(vec)
}

fn u32_to_ip(a: u32) -> IpAddr {
    IpAddr::V4(Ipv4Addr::from(a))
}

fn many_ip_addrs(addrs: Vec<u32>) -> Vec<IpAddr> {
    addrs.into_iter().map(|a| u32_to_ip(a)).collect()
}

fn ip_addr_pairs(addrs: Vec<u32>) -> Vec<(IpAddr, IpAddr)> {
    let (ips, masks): (Vec<_>, Vec<_>) = addrs.into_iter()
                                              .map(|e| u32_to_ip(e))
                                              .enumerate()
                                              .partition(|&(i, _)| i % 2 == 0);
    let ips: Vec<_> = ips.into_iter().map(|(_, v)| v).collect();
    let masks: Vec<_> = masks.into_iter().map(|(_, v)| v).collect();
    ips.into_iter()
       .zip(masks.into_iter())
       .collect()
}

fn num_u16s(bytes: &[u8]) -> IResult<&[u8], u8> {
    match be_u8(bytes) {
        IResult::Done(i, o) => IResult::Done(i, o / 2),
        a => a,
    }
}

fn num_u32s(bytes: &[u8]) -> IResult<&[u8], u8> {
    match be_u8(bytes) {
        IResult::Done(i, o) => IResult::Done(i, o / 4),
        a => a,
    }
}

macro_rules! ip_pairs(
    ($name:ident, $tag:expr, $variant:expr) => (
        named!($name<&[u8], DhcpOption>,
            do_parse!(
                tag!([$tag]) >>
                addrs: length_count!(num_u32s, be_u32) >>
                ({ $variant(ip_addr_pairs(addrs)) })
            )
        );
    )
);

/// A macro for the options that take the form
///
///     [tag, length, ip_addr...]
///
/// Since the only thing that really differs, is
/// the tag and the Enum variant that is returned
macro_rules! many_ips(
    ($name:ident, $tag:expr, $variant:expr) => (
        named!($name<&[u8], DhcpOption>,
            do_parse!(
                tag!([$tag]) >>
                addrs: length_count!(num_u32s, be_u32) >>
                ({ $variant(many_ip_addrs(addrs)) })
            )
        );
    )
);

/// A macro for options that are of the form:
///
///     [tag, length, somestring]
///
/// , since I haven't figured out a way to
/// easily construct a parser to take the length
/// out of a byte of the input, and parse that
/// many bytes into a string
macro_rules! length_specific_string(
    ($name:ident, $tag:expr, $variant:expr) => (
        named!($name<&[u8], DhcpOption>,
            do_parse!(
                tag!([$tag]) >>
                s: map_res!(sized_buffer, str::from_utf8) >>
                ({ $variant(s.to_owned()) })
            )
        );
    )
);

macro_rules! single_ip(
    ($name:ident, $tag:expr, $variant:expr) => (
        named!($name<&[u8], DhcpOption>,
            do_parse!(
                tag!([$tag]) >>
                _length: be_u8 >>
                addr: be_u32 >>
                ({ $variant(u32_to_ip(addr)) })
            )
        );
    )
);

macro_rules! bool(
    ($name:ident, $tag:expr, $variant:expr) => (
        named!($name<&[u8], DhcpOption>,
            do_parse!(
                tag!([$tag]) >>
                _length: be_u8 >>
                val: be_u8 >>
                ({ $variant(val == 1u8) })
            )
        );
    )
);

macro_rules! from_primitive(
    ($name:ident, $tag:expr, $variant:expr) => (
        named!($name<&[u8], DhcpOption>,
            do_parse!(
                tag!([$tag]) >>
                _l: be_u8 >>
                data: map_opt!(be_u8, FromPrimitive::from_u8) >>
                ({ $variant(data) })
            )
        );
    )
);

single_ip!(subnet_mask, 1u8, SubnetMask);

named!(time_offset<&[u8], DhcpOption>,
    do_parse!(
        tag!([2u8]) >>
        // length field, always 4
        be_u8 >>
        time: be_i32 >>
        ({ TimeOffset(time) })
    )
);

many_ips!(router, 3u8, Router);
many_ips!(time_server, 4u8, TimeServer);
many_ips!(name_server, 5u8, NameServer);
many_ips!(domain_name_server, 6u8, DomainNameServer);
many_ips!(log_server, 7u8, LogServer);
many_ips!(cookie_server, 8u8, CookieServer);
many_ips!(lpr_server, 9u8, LprServer);
many_ips!(impress_server, 10u8, ImpressServer);
many_ips!(resource_loc_server, 11u8, ResourceLocationServer);

length_specific_string!(hostname, 12u8, HostName);

named!(boot_file_size<&[u8], DhcpOption>,
    do_parse!(
        tag!([13u8]) >>
        _length: be_u8 >>
        s: be_u16 >>
        ({ BootFileSize(s) })
    )
);

length_specific_string!(merit_dump_file, 14u8, MeritDumpFile);
length_specific_string!(domain_name, 15u8, DomainName);
single_ip!(swap_server, 16u8, SwapServer);
length_specific_string!(root_path, 17u8, RootPath);
length_specific_string!(extensions_path, 18u8, ExtensionsPath);

// COLLECT ALL OF THE ABOVE INTO ONE PARSER
named!(vendor_extensions_rfc1497<&[u8], DhcpOption>, alt!(
        do_parse!(
            tag!([0u8]) >>
            ({ Pad })
        )
        | do_parse!(
            tag!([255u8]) >>
            ({ End })
        )
        | subnet_mask
        | time_offset
        | router
        | time_server
        | name_server         // 5
        | domain_name_server
        | log_server
        | cookie_server
        | lpr_server
        | impress_server      // 10
        | resource_loc_server
        | hostname
        | boot_file_size
        | merit_dump_file
        | domain_name         // 15
        | swap_server
        | root_path
        | extensions_path
    )
);

bool!(ip_forwarding, 19u8, IPForwarding);
bool!(non_source_local_routing, 20u8, NonLocalSourceRouting);
// TODO
/* named!(policy_filter<&[u8], DhcpOption>, */
/*     do_parse!( */
/*         tag!([21u8]) >> */
/*         s: map!(sized_buffer, ip_addr_pairs) >> */
/*         ({ PolicyFilter(s) }) */
/*     ) */
/* ); */
named!(max_datagram_reassembly_size<&[u8], DhcpOption>,
    do_parse!(
        tag!([22u8]) >>
        _len: be_u8 >>
        aa: be_u16 >>
        ({ MaxDatagramReassemblySize(aa) })
    )
);
named!(default_ip_ttl<&[u8], DhcpOption>,
    do_parse!(
        tag!([23u8]) >>
        _length: be_u8 >>
        ttl: be_u8 >>
        ({ DefaultIpTtl(ttl) })
    )
);
named!(path_mtu_aging_timeout<&[u8], DhcpOption>,
    do_parse!(
        tag!([24u8]) >>
        _length: be_u8 >>
        timeout: be_u32 >>
        ({ PathMtuAgingTimeout(timeout) })
    )
);
named!(path_mtu_plateau_table<&[u8], DhcpOption>,
    do_parse!(
        tag!([25u8]) >>
        sizes: length_count!(num_u16s, be_u16) >>
        ({ PathMtuPlateauTable(sizes) })
    )
);

// COLLECT
named!(ip_layer_parameters_per_host<&[u8], DhcpOption>, alt!(
          ip_forwarding
        | non_source_local_routing      // 20
        /* | policy_filter //TODO */
        | max_datagram_reassembly_size
        | default_ip_ttl
        | path_mtu_aging_timeout
        | path_mtu_plateau_table        // 25
    )
);

named!(interface_mtu<&[u8], DhcpOption>,
    do_parse!(
        tag!([26u8]) >>
        _length: be_u8 >>
        mtu: be_u16 >>
        ({ InterfaceMtu(mtu) })
    )
);
bool!(all_subnets_are_local, 27u8, AllSubnetsAreLocal);
single_ip!(broadcast_address, 28u8, BroadcastAddress);
bool!(perform_mask_discovery, 29u8, PerformMaskDiscovery);
bool!(mask_supplier, 30u8, MaskSupplier);
bool!(perform_router_discovery, 31u8, PerformRouterDiscovery);
single_ip!(router_solicitation_address, 32u8, RouterSolicitationAddress);
ip_pairs!(static_route, 33u8, StaticRoute);

// COLLECT
named!(ip_layer_parameters_per_interface<&[u8], DhcpOption>, alt!(
          interface_mtu
        | all_subnets_are_local
        | broadcast_address
        | perform_mask_discovery
        | mask_supplier                 // 30
        | perform_router_discovery
        | router_solicitation_address
        | static_route
    )
);

bool!(trailer_encapsulation, 34u8, TrailerEncapsulation);
named!(arp_cache_timeout<&[u8], DhcpOption>,
    do_parse!(
        tag!([35u8]) >>
        _length: be_u8 >>
        timeout: be_u32 >>
        ({ ArpCacheTimeout(timeout) })
    )
);
bool!(ethernet_encapsulation, 36u8, EthernetEncapsulation);

// COLLECT
named!(link_layer_parameters_per_interface<&[u8], DhcpOption>, alt!(
          trailer_encapsulation
        | arp_cache_timeout         // 35
        | ethernet_encapsulation
    )
);

named!(tcp_default_ttl<&[u8], DhcpOption>,
    do_parse!(
        tag!([37u8]) >>
        _length: be_u8 >>
        ttl: be_u8 >>
        ({ TcpDefaultTtl(ttl) })
    )
);
named!(tcp_keepalive_interval<&[u8], DhcpOption>,
    do_parse!(
        tag!([38u8]) >>
        _length: be_u8 >>
        interval: be_u32 >>
        ({ TcpKeepaliveInterval(interval) })
    )
);
bool!(tcp_keepalive_garbage, 39u8, TcpKeepaliveGarbage);

// COLLECT
named!(tcp_parameters<&[u8], DhcpOption>, alt!(
          tcp_default_ttl
        | tcp_keepalive_interval
        | tcp_keepalive_garbage
    )
);

length_specific_string!(nis_domain, 40u8, NisDomain);
many_ips!(network_information_servers, 41u8, NetworkInformationServers);
many_ips!(ntp_servers, 42u8, NtpServers);
named!(vendor_extensions<&[u8], DhcpOption>,
    do_parse!(
        tag!([43u8]) >>
        bytes: length_count!(be_u8, be_u8) >>
        ({ VendorExtensions(bytes) })
    )
);
many_ips!(net_bios_name_servers, 44u8, NetBiosNameServers);
many_ips!(net_bios_datagram_distribution_server, 45u8, NetBiosDatagramDistributionServer);
named!(net_bios_node_type<&[u8], DhcpOption>,
    do_parse!(
        tag!([46u8]) >>
        _length: be_u8 >>
        data: map_opt!(be_u8, FromPrimitive::from_u8) >>
        ({ NetBiosNodeType(data) })
    )
);
length_specific_string!(net_bios_scope, 47u8, NetBiosScope);
many_ips!(xfont_server, 48u8, XFontServer);
many_ips!(xdisplay_manager, 49u8, XDisplayManager);

// COLLECT
named!(application_and_service_parameters<&[u8], DhcpOption>, alt!(
          nis_domain                            // 40
        | network_information_servers
        | ntp_servers
        | vendor_extensions
        | net_bios_name_servers
        | net_bios_datagram_distribution_server // 45
        | net_bios_node_type
        | net_bios_scope
        | xfont_server
        | xdisplay_manager
    )
);

single_ip!(requested_ip_address, 50u8, RequestedIpAddress);
named!(ip_address_lease_time<&[u8], DhcpOption>,
    do_parse!(
        tag!([51u8]) >>
        _length: be_u8 >>
        time: be_u32 >>
        ({ IpAddressLeaseTime(time) })
    )
);
from_primitive!(option_overload, 52u8, OptionOverload);
from_primitive!(message_type, 53u8, MessageType);
single_ip!(server_identifier, 54u8, ServerIdentifier);
named!(param_request_list<&[u8], DhcpOption>,
    do_parse!(
        tag!([55u8]) >>
        data: length_count!(be_u8, be_u8) >>
        ({ ParamRequestList(data) })
    )
);
length_specific_string!(message, 56u8, Message);
named!(max_message_size<&[u8], DhcpOption>,
    do_parse!(
        tag!([57u8]) >>
        _l: be_u8 >>
        size_: be_u16 >>
        ({ MaxMessageSize(size_) })
    )
);

// COLLECT
named!(dhcp_extensions<&[u8], DhcpOption>, alt!(
          requested_ip_address  // 50
        | ip_address_lease_time
        | option_overload
        | message_type
        | server_identifier
        | param_request_list    // 55
        | message
        | max_message_size
/*         | renewal_time_value */
/*         | rebinding_time_value */
/*         | class_identifier      // 60 */
/*         | client_identifier */
    )
);

// Main parser
named!(dhcp_option(&[u8]) -> DhcpOption, alt!(
          vendor_extensions_rfc1497
        | ip_layer_parameters_per_host
        | ip_layer_parameters_per_interface
        | link_layer_parameters_per_interface
        | tcp_parameters
        | application_and_service_parameters
        | dhcp_extensions
        | relay_agent_information_option_rfc3046
    )
);

#[cfg(test)] mod tests {
    use options::DhcpOption;
    use options::DhcpOption::{ Router };
    use super::{ parse, router };
    use nom::IResult;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_many_ip_addresses() {
        let ips = vec![3u8,
                       8,
                       127, 0, 0, 1,
                       192, 168, 1, 1,
        ];

        match router(&ips) {
            IResult::Done(i, o) => {
                if i.len() > 0 {
                    panic!("Remaining input was {:?}", i);
                }
                assert_eq!(o, Router(vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                                          IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))]));
            },
            e => panic!("Result was {:?}", e),
        }
    }

    #[test]
    fn test_unknown_option() {
        let option = vec![
            0u8,
            254u8, 4u8, 192u8, 168u8, 1u8, 1u8,
            0u8,
            255u8
        ];
        let expected: Vec<DhcpOption> = vec![
            DhcpOption::Pad,
            DhcpOption::Pad,
            DhcpOption::End
        ];
        let actual = parse(&option).unwrap();
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_invalid_option_length_buffer_overrun() {
        // Declare an options length that is longer
        // than the remaning buffer
        let option = vec![
            0u8,
            12u8, 10u8, 1u8,
            255u8
        ];
        let expected: Vec<DhcpOption> = vec![
            DhcpOption::Pad,
        ];
        let actual = parse(&option).unwrap();
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_invalid_option_length_datatype_overflow() {
        // A option length at or near the bounds of the u8 datatype
        // could cause an overflow of any u8's that we're using for
        // length calculations, so we test how we handle that here
        let option = vec![
            0u8,
            12u8, 254u8,
            0u8,
            0u8,
            0u8,
            0u8,
            0u8,
            255u8
        ];
        let expected: Vec<DhcpOption> = vec![
            DhcpOption::Pad,
        ];
        let actual = parse(&option).unwrap();
        assert_eq!(expected, actual);

        let option = vec![
            0u8,
            12u8, 255u8,
            0u8,
            0u8,
            0u8,
            0u8,
            0u8,
            255u8
        ];
        let expected: Vec<DhcpOption> = vec![
            DhcpOption::Pad,
        ];
        let actual = parse(&option).unwrap();
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_option_000_pad_single() {
        let option = vec![
            0u8
        ];
        let expected: Vec<DhcpOption> = vec![
            DhcpOption::Pad
        ];
        let actual = parse(&option).unwrap();
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_option_000_pad_multiple() {
        let option = vec![
            0u8,
            0u8,
            0u8
        ];
        let expected: Vec<DhcpOption> = vec![
            DhcpOption::Pad,
            DhcpOption::Pad,
            DhcpOption::Pad
        ];
        let actual = parse(&option).unwrap();
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_option_050_requested_ip_address() {
        let option = vec![
            50u8,
            4u8,
            192u8,
            168u8,
            1u8,
            1u8,
        ];
        let expected: Vec<DhcpOption> = vec![
            DhcpOption::RequestedIpAddress(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
        ];
        let actual = parse(&option).unwrap();
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_option_051_ip_address_lease_time() {
        let option = vec![
            51u8,
            4u8,
            0u8,
            0u8,
            4u8,
            176u8,
        ];
        let expected: Vec<DhcpOption> = vec![
            DhcpOption::IpAddressLeaseTime(1200)
        ];
        let actual = parse(&option).unwrap();
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_option_053_dhcp_message_type() {
        use options::DhcpMessageTypes;
        // Parse all known options
        let options = vec![
            vec![ 53u8, 1u8, 1u8 ], // Discover
            vec![ 53u8, 1u8, 2u8 ], // Offer
            vec![ 53u8, 1u8, 3u8 ], // Request
            vec![ 53u8, 1u8, 4u8 ], // Decline
            vec![ 53u8, 1u8, 5u8 ], // Ack
            vec![ 53u8, 1u8, 6u8 ], // Nak
            vec![ 53u8, 1u8, 7u8 ], // Release
        ];
        let message_types = vec![
            DhcpMessageTypes::Discover,
            DhcpMessageTypes::Offer,
            DhcpMessageTypes::Request,
            DhcpMessageTypes::Decline,
            DhcpMessageTypes::Ack,
            DhcpMessageTypes::Nak,
            DhcpMessageTypes::Release,
        ];
        for (index, expected) in message_types.iter().enumerate() {
            if let &DhcpOption::MessageType(ref actual) = parse(&options[index]).unwrap().first().unwrap() {
                assert_eq!(expected, actual);
            } else {
                panic!("Failed to parse MessageType: {:?}", expected);
            }
        }
    }
}
