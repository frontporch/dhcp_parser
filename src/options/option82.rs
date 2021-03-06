use { Result };
use nom::{be_u8, be_u32, be_i32, IResult, sized_buffer};
use std::str;
use std::convert::{From};
use std::net::{IpAddr, Ipv4Addr};
use self::RelayAgentInformationSubOption::*;
use options::DhcpOption;
use options::DhcpOption::RelayAgentInformation;

#[allow(dead_code)]
#[derive(Debug, PartialEq)]
pub enum RelayAgentInformationSubOption {
    AgentCircuitID(Vec<u8>), // RFC 3046
    AgentRemoteID(Vec<u8>), // RFC 3046 	 	 
    DOCSISDeviceClass(i32), // RFC 3256
    LinkSelection(IpAddr), // RFC 3527
    SubscriberID(String), // RFC 3993
    RADIUSattributes(Vec<u8>), // RFC 4014
    Authentication(Vec<u8>), // RFC 4030
    VendorSpecificInformation(Vec<u8>), // RFC 4243
    RelayAgentFlags(u8), // RFC 5010
    ServerIdentifierOverride(i32), // RFC 5107
    DHCPv4VirtualSubnetSelection(Vec<u8>), // RFC 6607
    DHCPv4VirtualSubnetSelectionControl(Vec<u8>), // RFC 6607
}

fn u32_to_ip(a: u32) -> IpAddr {
    IpAddr::V4(Ipv4Addr::from(a))
}

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
        named!($name<&[u8], RelayAgentInformationSubOption>,
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
        named!($name<&[u8], RelayAgentInformationSubOption>,
            do_parse!(
                tag!([$tag]) >>
                _length: be_u8 >>
                addr: be_u32 >>
                ({ $variant(u32_to_ip(addr)) })
            )
        );
    )
);

named!(agent_circuit_id<&[u8], RelayAgentInformationSubOption>,
    do_parse!(
        tag!([1u8]) >>
        data: length_count!(be_u8, be_u8) >>
        ({ AgentCircuitID(data) })
    )
);

named!(agent_remote_id<&[u8], RelayAgentInformationSubOption>,
    do_parse!(
        tag!([2u8]) >>
        data: length_count!(be_u8, be_u8) >>
        ({ AgentRemoteID(data) })
    )
);

named!(docsis_device_class<&[u8], RelayAgentInformationSubOption>,
    do_parse!(
        tag!([4u8]) >>
        // length field, always 4
        be_u8 >>
        device_class: be_i32 >>
        ({ DOCSISDeviceClass(device_class) })
    )
);
single_ip!(link_selection, 5u8, LinkSelection);
length_specific_string!(subscriber_id, 6u8, SubscriberID);
named!(radius_attributes<&[u8], RelayAgentInformationSubOption>,
    do_parse!(
        tag!([7u8]) >>
        data: length_count!(be_u8, be_u8) >>
        ({ RADIUSattributes(data) })
    )
);
named!(authentication<&[u8], RelayAgentInformationSubOption>,
    do_parse!(
        tag!([8u8]) >>
        data: length_count!(be_u8, be_u8) >>
        ({ Authentication(data) })
    )
);
named!(vendor_specific_information<&[u8], RelayAgentInformationSubOption>,
    do_parse!(
        tag!([9u8]) >>
        data: length_count!(be_u8, be_u8) >>
        ({ VendorSpecificInformation(data) })
    )
);
named!(relay_agent_flags<&[u8], RelayAgentInformationSubOption>,
    do_parse!(
        tag!([10u8]) >>
        _length: be_u8 >>
        relay_agent_flag: be_u8 >>
        ({ RelayAgentFlags(relay_agent_flag) })
    )
);
named!(server_identifier_override<&[u8], RelayAgentInformationSubOption>,
    do_parse!(
        tag!([11u8]) >>
        // length field, always 4
        be_u8 >>
        identifier: be_i32 >>
        ({ ServerIdentifierOverride(identifier) })
    )
);
named!(dhcp_v4_virtual_subnet_selection<&[u8], RelayAgentInformationSubOption>,
    do_parse!(
        tag!([151u8]) >>
        data: length_count!(be_u8, be_u8) >>
        ({ DHCPv4VirtualSubnetSelection(data) })
    )
);
named!(dhcp_v4_virtual_subnet_selection_control<&[u8], RelayAgentInformationSubOption>,
    do_parse!(
        tag!([152u8]) >>
        data: length_count!(be_u8, be_u8) >>
        ({ DHCPv4VirtualSubnetSelectionControl(data) })
    )
);

// COLLECT
named!(option_82_parser<&[u8], RelayAgentInformationSubOption>, alt!(
          agent_circuit_id
        | agent_remote_id
        | docsis_device_class
        | link_selection
        | subscriber_id
        | radius_attributes
        | authentication
        | vendor_specific_information
        | relay_agent_flags
        | server_identifier_override
        | dhcp_v4_virtual_subnet_selection
        | dhcp_v4_virtual_subnet_selection_control
    )
);

fn parse(bytes: &[u8]) -> Result<Vec<RelayAgentInformationSubOption>> {
    let mut vec = Vec::new();
    if bytes.len() > 0 {
        let mut remaining = Some(bytes);
        while let Some(unparsed) = remaining {
            // Do some basic sanity checks before actually parsing
            match unparsed.len() {
                0 | 1 | 2 => {
                    // Shouldn't get here, but just in case
                    remaining = None;
                    continue;
                },
                _ => {
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
                },
            }

            // If an option was successfully parsed
            if let IResult::Done(rest, opt) = option_82_parser(unparsed) {
                // If this is the end of options
                if rest.len() < 3 {
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

named!(pub relay_agent_information_option_rfc3046<&[u8], DhcpOption>,
    do_parse!(
        tag!([82u8]) >>
        data: map_res!(sized_buffer, parse) >>
        ({ RelayAgentInformation(data) })
    )
);

#[cfg(test)] mod option_82_tests {
    use super::RelayAgentInformationSubOption::*;
    use super::relay_agent_information_option_rfc3046;
    use std::net::{IpAddr, Ipv4Addr};
    use nom::IResult;
    use options::DhcpOption::RelayAgentInformation;


    #[test]
    fn test_unknown_option() {
        let option = [
            82u8,   // Option 82
            16u8,    // Option 82 Length
            150u8,    // Suboption (Unknown)
            6u8,    // Suboption Length
            0u8, 1u8, 2u8, 3u8, 4u8, 5u8,
            1u8,    // Suboption
            6u8,    // Suboption Length
            0u8, 1u8, 2u8, 3u8, 4u8, 5u8,
        ];
        let expected = RelayAgentInformation(vec![ AgentCircuitID(vec![ 0u8, 1u8, 2u8, 3u8, 4u8, 5u8 ]) ]);
        match relay_agent_information_option_rfc3046(&option) {
            IResult::Done(remaning, actual) => {
                if remaning.len() > 0 { panic!("Remaining input was {:?}", remaning); }
                assert_eq!(expected, actual);
            },
            e => panic!("Result was {:?}", e),
        }
    }

    #[test]
    fn test_invalid_option_length_buffer_overrun() {
        let option = [
            82u8,   // Option 82
            16u8,    // Option 82 Length
            1u8,    // Suboption
            6u8,    // Suboption Length
            0u8, 1u8, 2u8, 3u8, 4u8, 5u8,
            2u8,    // Suboption
            100u8,    // Suboption Length (Invalid)
            0u8, 1u8, 2u8, 3u8, 4u8, 5u8,
        ];
        let expected = RelayAgentInformation(vec![ AgentCircuitID(vec![ 0u8, 1u8, 2u8, 3u8, 4u8, 5u8 ]) ]);
        match relay_agent_information_option_rfc3046(&option) {
            IResult::Done(remaning, actual) => {
                if remaning.len() > 0 { panic!("Remaining input was {:?}", remaning); }
                assert_eq!(expected, actual);
            },
            e => panic!("Result was {:?}", e),
        }
    }

    #[test]
    fn test_invalid_option_length_datatype_overflow() {
        // A option length at or near the bounds of the u8 datatype
        // could cause an overflow of any u8's that we're using for
        // length calculations, so we test how we handle that here
        let option = [
            82u8,   // Option 82
            16u8,    // Option 82 Length
            1u8,    // Suboption
            6u8,    // Suboption Length
            0u8, 1u8, 2u8, 3u8, 4u8, 5u8,
            2u8,    // Suboption
            254u8,    // Suboption Length (Invalid)
            0u8, 1u8, 2u8, 3u8, 4u8, 5u8,
        ];
        let expected = RelayAgentInformation(vec![ AgentCircuitID(vec![ 0u8, 1u8, 2u8, 3u8, 4u8, 5u8 ]) ]);
        match relay_agent_information_option_rfc3046(&option) {
            IResult::Done(remaning, actual) => {
                if remaning.len() > 0 { panic!("Remaining input was {:?}", remaning); }
                assert_eq!(expected, actual);
            },
            e => panic!("Result was {:?}", e),
        }

        let option = [
            82u8,   // Option 82
            16u8,    // Option 82 Length
            1u8,    // Suboption
            6u8,    // Suboption Length
            0u8, 1u8, 2u8, 3u8, 4u8, 5u8,
            2u8,    // Suboption
            255u8,    // Suboption Length (Invalid)
            0u8, 1u8, 2u8, 3u8, 4u8, 5u8,
        ];
        let expected = RelayAgentInformation(vec![ AgentCircuitID(vec![ 0u8, 1u8, 2u8, 3u8, 4u8, 5u8 ]) ]);
        match relay_agent_information_option_rfc3046(&option) {
            IResult::Done(remaning, actual) => {
                if remaning.len() > 0 { panic!("Remaining input was {:?}", remaning); }
                assert_eq!(expected, actual);
            },
            e => panic!("Result was {:?}", e),
        }
    }

    #[test]
    fn test_suboption_001_agent_circuit_id() {
        let option = [
            82u8,   // Option 82
            8u8,    // Option 82 Length
            1u8,    // Suboption
            6u8,    // Suboption Length
            0u8, 1u8, 2u8, 3u8, 4u8, 5u8
        ];
        let expected = RelayAgentInformation(vec![ AgentCircuitID(vec![ 0u8, 1u8, 2u8, 3u8, 4u8, 5u8 ]) ]);
        match relay_agent_information_option_rfc3046(&option) {
            IResult::Done(remaning, actual) => {
                if remaning.len() > 0 { panic!("Remaining input was {:?}", remaning); }
                assert_eq!(expected, actual);
            },
            e => panic!("Result was {:?}", e),
        }
    }

    #[test]
    fn test_suboption_002_agent_remote_id() {
        let option = [
            82u8,   // Option 82
            8u8,    // Option 82 Length
            2u8,    // Suboption
            6u8,    // Suboption Length
            0u8, 1u8, 2u8, 3u8, 4u8, 5u8
        ];
        let expected = RelayAgentInformation(vec![ AgentRemoteID(vec![ 0u8, 1u8, 2u8, 3u8, 4u8, 5u8 ]) ]);
        match relay_agent_information_option_rfc3046(&option) {
            IResult::Done(remaning, actual) => {
                if remaning.len() > 0 { panic!("Remaining input was {:?}", remaning); }
                assert_eq!(expected, actual);
            },
            e => panic!("Result was {:?}", e),
        }
    }

    #[test]
    fn test_suboption_004_docsis_device_class() {
        let option = [
            82u8,   // Option 82
            6u8,    // Option 82 Length
            4u8,    // Suboption
            4u8,    // Suboption Length
            0u8, 0u8, 0u8, 1u8
        ];
        let expected = RelayAgentInformation(vec![ DOCSISDeviceClass(1) ]);
        match relay_agent_information_option_rfc3046(&option) {
            IResult::Done(remaning, actual) => {
                if remaning.len() > 0 { panic!("Remaining input was {:?}", remaning); }
                assert_eq!(expected, actual);
            },
            e => panic!("Result was {:?}", e),
        }
    }

    #[test]
    fn test_suboption_005_link_selection() {
        let option = [
            82u8,   // Option 82
            6u8,    // Option 82 Length
            5u8,    // Suboption
            4u8,    // Suboption Length
            192u8, 168u8, 1u8, 1u8
        ];
        let expected = RelayAgentInformation(vec![ LinkSelection(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))) ]);
        match relay_agent_information_option_rfc3046(&option) {
            IResult::Done(remaning, actual) => {
                if remaning.len() > 0 { panic!("Remaining input was {:?}", remaning); }
                assert_eq!(expected, actual);
            },
            e => panic!("Result was {:?}", e),
        }
    }

    #[test]
    fn test_suboption_006_subscriber_id() {
        let option = [
            82u8,   // Option 82
            6u8,    // Option 82 Length
            6u8,    // Suboption
            4u8,    // Suboption Length
            84u8, 101u8, 115u8, 116u8
        ];
        let expected = RelayAgentInformation(vec![ SubscriberID("Test".to_string()) ]);
        match relay_agent_information_option_rfc3046(&option) {
            IResult::Done(remaning, actual) => {
                if remaning.len() > 0 { panic!("Remaining input was {:?}", remaning); }
                assert_eq!(expected, actual);
            },
            e => panic!("Result was {:?}", e),
        }
    }

    #[test]
    fn test_suboption_007_radius_attributes() {
        let option = [
            82u8,   // Option 82
            8u8,    // Option 82 Length
            7u8,    // Suboption
            6u8,    // Suboption Length
            0u8, 1u8, 2u8, 3u8, 4u8, 5u8
        ];
        let expected = RelayAgentInformation(vec![ RADIUSattributes(vec![ 0u8, 1u8, 2u8, 3u8, 4u8, 5u8 ]) ]);
        match relay_agent_information_option_rfc3046(&option) {
            IResult::Done(remaning, actual) => {
                if remaning.len() > 0 { panic!("Remaining input was {:?}", remaning); }
                assert_eq!(expected, actual);
            },
            e => panic!("Result was {:?}", e),
        }
    }

    #[test]
    fn test_suboption_008_authentication() {
        let option = [
            82u8,   // Option 82
            8u8,    // Option 82 Length
            8u8,    // Suboption
            6u8,    // Suboption Length
            0u8, 1u8, 2u8, 3u8, 4u8, 5u8
        ];
        let expected = RelayAgentInformation(vec![ Authentication(vec![ 0u8, 1u8, 2u8, 3u8, 4u8, 5u8 ]) ]);
        match relay_agent_information_option_rfc3046(&option) {
            IResult::Done(remaning, actual) => {
                if remaning.len() > 0 { panic!("Remaining input was {:?}", remaning); }
                assert_eq!(expected, actual);
            },
            e => panic!("Result was {:?}", e),
        }
    }

    #[test]
    fn test_suboption_009_vendor_specific_information() {
        let option = [
            82u8,   // Option 82
            8u8,    // Option 82 Length
            9u8,    // Suboption
            6u8,    // Suboption Length
            0u8, 1u8, 2u8, 3u8, 4u8, 5u8
        ];
        let expected = RelayAgentInformation(vec![ VendorSpecificInformation(vec![ 0u8, 1u8, 2u8, 3u8, 4u8, 5u8 ]) ]);
        match relay_agent_information_option_rfc3046(&option) {
            IResult::Done(remaning, actual) => {
                if remaning.len() > 0 { panic!("Remaining input was {:?}", remaning); }
                assert_eq!(expected, actual);
            },
            e => panic!("Result was {:?}", e),
        }
    }

    #[test]
    fn test_suboption_010_relay_agent_flags() {
        let option = [
            82u8,   // Option 82
            3u8,    // Option 82 Length
            10u8,    // Suboption
            1u8,    // Suboption Length
            123u8
        ];
        let expected = RelayAgentInformation(vec![ RelayAgentFlags(123u8) ]);
        match relay_agent_information_option_rfc3046(&option) {
            IResult::Done(remaning, actual) => {
                if remaning.len() > 0 { panic!("Remaining input was {:?}", remaning); }
                assert_eq!(expected, actual);
            },
            e => panic!("Result was {:?}", e),
        }
    }

    #[test]
    fn test_suboption_011_server_identifier_override() {
        let option = [
            82u8,   // Option 82
            6u8,    // Option 82 Length
            11u8,    // Suboption
            4u8,    // Suboption Length
            0u8, 0u8, 0u8, 1u8
        ];
        let expected = RelayAgentInformation(vec![ ServerIdentifierOverride(1) ]);
        match relay_agent_information_option_rfc3046(&option) {
            IResult::Done(remaning, actual) => {
                if remaning.len() > 0 { panic!("Remaining input was {:?}", remaning); }
                assert_eq!(expected, actual);
            },
            e => panic!("Result was {:?}", e),
        }
    }

    #[test]
    fn test_suboption_151_dhcp_v4_virtual_subnet_selection() {
        let option = [
            82u8,   // Option 82
            8u8,    // Option 82 Length
            151u8,    // Suboption
            6u8,    // Suboption Length
            0u8, 1u8, 2u8, 3u8, 4u8, 5u8
        ];
        let expected = RelayAgentInformation(vec![ DHCPv4VirtualSubnetSelection(vec![ 0u8, 1u8, 2u8, 3u8, 4u8, 5u8 ]) ]);
        match relay_agent_information_option_rfc3046(&option) {
            IResult::Done(remaning, actual) => {
                if remaning.len() > 0 { panic!("Remaining input was {:?}", remaning); }
                assert_eq!(expected, actual);
            },
            e => panic!("Result was {:?}", e),
        }
    }

    #[test]
    fn test_suboption_152_dhcp_v4_virtual_subnet_selection_control() {
        let option = [
            82u8,   // Option 82
            8u8,    // Option 82 Length
            152u8,    // Suboption
            6u8,    // Suboption Length
            0u8, 1u8, 2u8, 3u8, 4u8, 5u8
        ];
        let expected = RelayAgentInformation(vec![ DHCPv4VirtualSubnetSelectionControl(vec![ 0u8, 1u8, 2u8, 3u8, 4u8, 5u8 ]) ]);
        match relay_agent_information_option_rfc3046(&option) {
            IResult::Done(remaning, actual) => {
                if remaning.len() > 0 { panic!("Remaining input was {:?}", remaning); }
                assert_eq!(expected, actual);
            },
            e => panic!("Result was {:?}", e),
        }
    }
}
