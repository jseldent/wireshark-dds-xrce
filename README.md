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

### HelloWorld example

The HelloWorld examples in
[Micro-XRCE-DDS-Client](https://github.com/eProsima/Micro-XRCE-DDS-Client) all
publish their messages on the `HelloWorldTopic` topic with the following data
type:
``` idl
struct HelloWorld {
  unsigned long index;
  string message;
};
```

To enable the dissector to deserialize these messages, create the
`~/.local/lib/wireshark/plugins/HelloWorld.lua` file, containing:
``` lua
require "dds-xrce-idl"

local function HelloWorld_deserialize(tvb, offset, encoding, tree, label)
    local subtree = tree:add(tvb(offset), label)
    local subtree_begin = offset

    offset = unsigned_long_deserialize(tvb, offset, encoding, subtree, "index:")
    offset = string_deserialize(tvb, offset, encoding, subtree, "message:")

    subtree:set_len(offset - subtree_begin)

    return offset
end
types["HelloWorld"] = HelloWorld_deserialize
```

The examples create the DDS entities with a Qos XML string, in which case this
is enough information.

If, instead, you create the entities with a reference to a profile in the QoS
XML supplied to the agent, you need to provide some more information. First,
associate the data type with a topic by adding the following line to
`HelloWorld.lua`:
``` lua
topic_type_names["HelloWorldTopic"] = "HelloWorld"
```
Second, associate the topic name with the profile references by adding the
following three lines:
``` lua
topic_names["my_topic_profile"] = "HelloWorldTopic"
data_reader_topic_names["my_data_reader_profile"] = "HelloWorldTopic"
data_writer_topic_names["my_data_writer_profile"] = "HelloWorldTopic"
```

Capturing the packets of the `PublishHelloWorld` example results in the
following dissection:
![PublishHelloWorld](PublishHelloWorld.png)
