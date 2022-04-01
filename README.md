# DDS-XRCE Protocol dissector for Wireshark

This is a Wireshark dissector for the DDS for eXtremely Resource Constrained
Environments ([DDS-XRCE](https://www.omg.org/spec/DDS-XRCE/1.0/About-DDS-XRCE/))
protocol. In particular the
[Micro-XRCE-DDS](https://github.com/eProsima/Micro-XRCE-DDS) implementation.

The dissector handles both UDP and TCP transports. To support the Micro-XRCE-DDS
examples out of the box, it assumes that the agent and client communicate over
port 2018, but this can be changed in the preferences.

## Installation

To use the dissector, copy `dds-xrce-idl.lua`, `dds-xrce-proto.lua` and
`dds-xrce-types.lua` to `~/.local/lib/wireshark/plugins` and (re)start
Wireshark.

## Used-defined data types

The dissector is capable of deserializing user-defined data types, provided
- Wireshark captures the packets that create the DDS entities (topics,
  datareaders and datawriters),
- deserialization functions are registered for the data types,
- and only a single client is connected to the agent.
