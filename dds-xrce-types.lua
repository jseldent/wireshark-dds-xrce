-- DDS-XRCE Types dissector for Wireshark
--
-- Copyright 2022 Lely Industries N.V.
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.

require "dds-xrce-idl"

dds_xrce_types = {}

local track_objects = true
local deserialize_types = true

local object_id = 0
local object_profile_names = {}
local object_topic_names = {}
local object_type_names = {}

function dds_xrce_types_init(track, deserialize)
    track_objects = track
    deserialize_types = deserialize
end

function dds_xrce_types_menu(group)
    local function reset_objects()
        object_id = 0
        object_profile_names = {}
        object_topic_names = {}
        object_type_names = {}

        redissect_packets()
    end
    register_menu("DDS-XRCE/Reset objects", reset_objects, group)

    local function set_object()
        local function action(id, profile_name, topic_name, type_name)
            if profile_name ~= nil and profile_name ~= "" then
                object_profile_names[tonumber(id)] = profile_name
            end
            if topic_name ~= nil and topic_name ~= "" then
                object_topic_names[tonumber(id)] = topic_name
            end
            if type_name ~= nil and type_name ~= "" then
                object_type_names[tonumber(id)] = type_name
            end
            redissect_packets()
        end
        local id = string.format("0x%04X", object_id)
        local profile_name = object_profile_names[object_id]
        local topic_name = object_topic_names[object_id]
        local type_name = object_type_names[object_id]
        if type_name == nil and topic_name ~= nil then
            type_name = topic_type_names[topic_name]
        end
        new_dialog(
            "Set object",
            action,
            {name = "ID", value = id},
            {name = "profile", value = profile_name},
            {name = "topic", value = topic_name},
            {name = "type", value = type_name}
        )
    end
    register_menu("DDS-XRCE/Set object...", set_object, group)
end

local XML_PROFILE_NAME_PATTERN = "%s+profile_name%s*=%s*\"([^\"]*)\""
local XML_NAME_PATTERN = "<name%s*>%s*([^%s<]*)%s*</name%s*>"
local XML_DATA_TYPE_PATTERN = "<dataType%s*>%s*([^%s<]*)%s*</dataType%s*>"

local function ClientKey_deserialize(tvb, offset, encoding, tree, label)
    tree:add(tvb(offset, 4), label, tvb(offset, 4):bytes():tohex(true))
    offset = offset + 4

    return offset
end

local function ObjectId_deserialize(tvb, offset, encoding, tree, label)
    local object_id_0 = tvb(offset, 1):uint()
    local object_id_1 = tvb(offset + 1, 1):uint()
    local subtree = tree:add(tvb(offset, 2), label, tvb(offset, 2):bytes():tohex(true))
    if object_id_0 == 0xFF and object_id_1 == 0xFF then
        subtree:append_text(" (SESSION)")
    elseif bit.band(object_id_1, 0x0F) == 0x00 then
        subtree:append_text(" (INVALID)")
    elseif bit.band(object_id_1, 0x0F) == 0x01 then
        subtree:append_text(" (PARTICIPANT)")
    elseif bit.band(object_id_1, 0x0F) == 0x02 then
        subtree:append_text(" (TOPIC)")
    elseif bit.band(object_id_1, 0x0F) == 0x03 then
        subtree:append_text(" (PUBLISHER)")
    elseif bit.band(object_id_1, 0x0F) == 0x04 then
        subtree:append_text(" (SUBSCRIBER)")
    elseif bit.band(object_id_1, 0x0F) == 0x05 then
        subtree:append_text(" (DATAWRITER)")
    elseif bit.band(object_id_1, 0x0F) == 0x06 then
        subtree:append_text(" (DATAREADER)")
    elseif bit.band(object_id_1, 0x0F) == 0x0A then
        subtree:append_text(" (TYPE)")
    elseif bit.band(object_id_1, 0x0F) == 0x0B then
        subtree:append_text(" (QOSPROFILE)")
    elseif bit.band(object_id_1, 0x0F) == 0x0C then
        subtree:append_text(" (APPLICATION)")
    elseif bit.band(object_id_1, 0x0F) == 0x0D then
        subtree:append_text(" (AGENT)")
    elseif bit.band(object_id_1, 0x0F) == 0x0E then
        subtree:append_text(" (CLIENT)")
    end
    if track_objects then
        local id = tvb(offset, 2):uint()
        local profile_name = object_profile_names[id]
        if profile_name ~= nil then
            subtree:add("profile:", profile_name):set_generated(true)
        end
        local topic_name = object_topic_names[id]
        local type_name = object_type_names[id]
        if topic_name ~= nil then
            subtree:add("topic:", topic_name):set_generated(true)
            if type_name == nil then
                type_name = topic_type_names[topic_name]
            end
        end
        if type_name ~= nil then
            subtree:add("type:", type_name):set_generated(true)
        end
    end
    offset = offset + 2

    return offset
end

local function XrceCookie_deserialize(tvb, offset, encoding, tree, label)
    tree:add(tvb(offset, 4), label, tvb(offset, 4):string())
    offset = offset + 4

    return offset
end

local function XrceVersion_deserialize(tvb, offset, encoding, tree, label)
    local xrce_version_major = tvb(offset, 1):uint()
    local xrce_version_minor = tvb(offset + 1, 1):uint()
    local xrce_version = tostring(xrce_version_major) .. "." .. tostring(xrce_version_minor)
    local subtree = tree:add(tvb(offset, 2), label, xrce_version)
    subtree:add(tvb(offset, 1), "major:", xrce_version_major)
    subtree:add(tvb(offset + 1, 1), "minor:", xrce_version_minor)
    offset = offset + 2

    return offset
end

local function XrceVendorId_deserialize(tvb, offset, encoding, tree, label)
    local xrce_vendor_id_major = tvb(offset, 1):uint()
    local xrce_vendor_id_minor = tvb(offset + 1, 1):uint()
    local subtree =
        tree:add(tvb(offset, 2), label, tostring(xrce_vendor_id_major) .. "." .. tostring(xrce_vendor_id_minor))
    if xrce_vendor_id_major == 0 and xrce_vendor_id_minor == 0 then
        subtree:append_text(" (INVALID)")
    elseif xrce_vendor_id_major == 1 and xrce_vendor_id_minor == 15 then
        subtree:append_text(" (eProsima)")
    end
    offset = offset + 2

    return offset
end

local function Time_t_deserialize(tvb, offset, encoding, tree, label)
    offset = align(offset, 4)

    local nstime = ""
    if encoding == ENC_BIG_ENDIAN then
        nstime = tostring(tvb(offset, 8):nstime())
    elseif encoding == ENC_LITTLE_ENDIAN then
        nstime = tostring(tvb(offset, 8):le_nstime())
    end
    local subtree = tree:add(tvb(offset, 8), label, nstime)
    subtree:add(tvb(offset, 4), "seconds:", tvb_int(tvb(offset, 4), encoding))
    offset = offset + 4
    subtree:add(tvb(offset, 4), "nanoseconds:", tvb_uint(tvb(offset, 4), encoding))
    offset = offset + 4

    return offset
end

local function SessionId_deserialize(tvb, offset, encoding, tree, label)
    local session_id = tvb(offset, 1):uint()
    local subtree = tree:add(tvb(offset, 1), label, string.format("0x%02X", session_id))
    if session_id == 0x00 then
        subtree:append_text(" (SESSION_ID_NONE_WITH_CLIENT_KEY)")
    elseif session_id == 0x80 then
        subtree:append_text(" (SESSION_ID_NONE_WITHOUT_CLIENT_KEY)")
    end
    offset = offset + 1

    return offset
end

local function StreamId_deserialize(tvb, offset, encoding, tree, label)
    local stream_id = tvb(offset, 1):uint()
    local subtree = tree:add(tvb(offset, 1), label, string.format("0x%02X", stream_id))
    if stream_id == 0x00 then
        subtree:append_text(" (STREAMID_NONE)")
    elseif session_id == 0x01 then
        subtree:append_text(" (STREAMID_BUILTIN_BEST_EFFORTS)")
    elseif session_id == 0x80 then
        subtree:append_text(" (STREAMID_BUILTIN_RELIABLE)")
    end
    if stream_id >= 0x80 then
        subtree:add(tvb(offset, 1), "reliability:", "RELIABLE")
    elseif stream_id >= 0x01 then
        subtree:add(tvb(offset, 1), "reliability:", "BEST_EFFORTS")
    end
    offset = offset + 1

    return offset
end

local function TransportLocatorSmall_deserialize(tvb, offset, encoding, tree, label)
    local subtree = tree:add(tvb(offset, 3), label)

    subtree:add(tvb(offset, 2), "address:", tvb(offset, 2):bytes():tohex(true, " "))
    offset = offset + 2
    offset = octet_deserialize(tvb, offset, encoding, subtree, "locator_port:")

    return offset
end

local function TransportLocatorMedium_deserialize(tvb, offset, encoding, tree, label)
    local subtree = tree:add(tvb(offset), label)
    local subtree_begin = offset

    subtree:add(tvb(offset, 4), "address:", tostring(tvb(offset, 4):ipv4()))
    offset = offset + 4

    offset = unsigned_short_deserialize(tvb, offset, encoding, subtree, "locator_port:")

    subtree:set_len(offset - subtree_begin)

    return offset
end

local function TransportLocatorLarge_deserialize(tvb, offset, encoding, tree, label)
    local subtree = tree:add(tvb(offset), label)
    local subtree_begin = offset

    subtree:add(tvb(offset, 16), "address:", tostring(tvb(offset, 16):ipv6()))
    offset = offset + 16

    offset = unsigned_long_deserialize(tvb, offset, encoding, subtree, "locator_port:")

    subtree:set_len(offset - subtree_begin)

    return offset
end

local function TransportLocatorString_deserialize(tvb, offset, encoding, tree, label)
    local subtree = tree:add(tvb(offset), label)
    local subtree_begin = offset

    offset = string_deserialize(tvb, offset, encoding, subtree, "string_locator:")

    subtree:set_len(offset - subtree_begin)

    return offset
end

local function TransportLocator_deserialize(tvb, offset, encoding, tree, label)
    local subtree = tree:add(tvb(offset), label)
    local subtree_begin = offset

    local format = tvb(offset, 1):uint()
    local t_format = subtree:add(tvb(offset, 1), "format:", string.format("0x%02X", format))
    offset = offset + 1

    if format == 0x00 then
        -- ADDRES_FORMAT_SMALL
        t_format:append_text(" (ADDRES_FORMAT_SMALL)")
        offset = TransportLocatorSmall_deserialize(tvb, offset, encoding, subtree, "small_locator")
    elseif format == 0x01 then
        -- ADDRES_FORMAT_MEDIUM
        t_format:append_text(" (ADDRES_FORMAT_MEDIUM)")
        offset = TransportLocatorMedium_deserialize(tvb, offset, encoding, subtree, "medium_locator")
    elseif format == 0x02 then
        -- ADDRES_FORMAT_LARGE
        t_format:append_text(" (ADDRES_FORMAT_LARGE)")
        offset = TransportLocatorLarge_deserialize(tvb, offset, encoding, subtree, "large_locator")
    elseif format == 0x03 then
        -- ADDRES_FORMAT_STRING
        t_format:append_text(" (ADDRES_FORMAT_STRING)")
        offset = TransportLocatorString_deserialize(tvb, offset, encoding, subtree, "string_locator")
    end

    subtree:set_len(offset - subtree_begin)

    return offset
end

local function TransportLocatorSeq_deserialize(tvb, offset, encoding, tree, label)
    return sequence_deserialize(tvb, offset, encoding, tree, label, TransportLocator_deserialize)
end

local function Property_deserialize(tvb, offset, encoding, tree)
    offset = align(offset, 4)
    local begin = offset
    local name_size = tvb_uint(tvb(offset, 4), encoding)
    offset = offset + 4
    local name = tvb(offset, name_size):stringz()
    offset = offset + name_size

    offset = align(offset, 4)
    local value_size = tvb_uint(tvb(offset, 4), encoding)
    offset = offset + 4
    local value = tvb(offset, value_size):stringz()
    offset = offset + value_size

    tree:add(tvb(begin, offset - begin), name .. ":", value)

    return offset
end

local function PropertySeq_deserialize(tvb, offset, encoding, tree, label)
    offset = align(offset, 4)

    local subtree = tree:add(tvb(offset), label)
    local subtree_begin = offset

    local size = tvb_uint(tvb(offset, 4), encoding)
    offset = offset + 4
    if size == 0 then
        subtree:append_text(" [empty]")
    else
        for i = 1, size do
            offset = Property_deserialize(tvb, offset, encoding, subtree)
        end
    end

    subtree:set_len(offset - subtree_begin)

    return offset
end

local function CLIENT_Representation_deserialize(tvb, offset, encoding, tree, label)
    local subtree = tree:add(tvb(offset), label)
    local subtree_begin = offset

    offset = XrceCookie_deserialize(tvb, offset, encoding, subtree, "xrce_cookie:")
    offset = XrceVersion_deserialize(tvb, offset, encoding, subtree, "xrce_version:")
    offset = XrceVendorId_deserialize(tvb, offset, encoding, subtree, "xrce_vendor_id:")
    offset = ClientKey_deserialize(tvb, offset, encoding, subtree, "client_key:")
    offset = SessionId_deserialize(tvb, offset, encoding, subtree, "session_id:")
    offset = optional_deserialize(tvb, offset, encoding, subtree, "properties", PropertySeq_deserialize)

    subtree:set_len(offset - subtree_begin)

    return offset
end

local function AGENT_Representation_deserialize(tvb, offset, encoding, tree, label)
    local subtree = tree:add(tvb(offset), label)
    local subtree_begin = offset

    offset = XrceCookie_deserialize(tvb, offset, encoding, subtree, "xrce_cookie:")
    offset = XrceVersion_deserialize(tvb, offset, encoding, subtree, "xrce_version:")
    offset = XrceVendorId_deserialize(tvb, offset, encoding, subtree, "xrce_vendor_id:")
    offset = optional_deserialize(tvb, offset, encoding, subtree, "properties", PropertySeq_deserialize)

    subtree:set_len(offset - subtree_begin)

    return offset
end

local function OBJK_DomainParticipant_Binary_deserialize(tvb, offset, encoding, tree, label)
    local subtree = tree:add(tvb(offset), label)
    local subtree_begin = offset

    offset = optional_deserialize(tvb, offset, encoding, subtree, "domain_reference:", string_deserialize)
    offset = optional_deserialize(tvb, offset, encoding, subtree, "qos_profile_reference:", string_deserialize)

    subtree:set_len(offset - subtree_begin)

    return offset
end

local function OBJK_Topic_Binary_deserialize(tvb, offset, encoding, tree, label)
    offset = align(offset, 4)

    local subtree = tree:add(tvb(offset), label)
    local subtree_begin = offset

    local size = tvb_uint(tvb(offset, 4), encoding)
    offset = offset + 4
    local topic_name = tvb(offset, size):stringz()
    subtree:add(tvb(offset, size), "topic_name:", topic_name)
    offset = offset + size
    if track_objects then
        -- Register the topic name for this object.
        object_topic_names[object_id] = topic_name
    end

    offset = optional_deserialize(tvb, offset, encoding, subtree, "type_reference:", string_deserialize)

    -- WARNING: This is `@optional DDS:XTypes::TypeIdentifier type_identifier;` in the official dds_xrce_types.idl.
    local has_type_name = tvb(offset, 1):uint()
    offset = offset + 1
    if has_type_name > 0 then
        offset = align(offset, 4)
        local size = tvb_uint(tvb(offset, 4), encoding)
        offset = offset + 4
        local type_name = tvb(offset, size):stringz()
        subtree:add(tvb(offset, size), "type_name:", type_name)
        offset = offset + size
        if track_objects then
            -- Register the type name for this object.
            topic_type_names[topic_name] = type_name
        end
    end

    subtree:set_len(offset - subtree_begin)

    return offset
end

local function OBJK_Publisher_Binary_Qos_deserialize(tvb, offset, encoding, tree, label)
    local subtree = tree:add(tvb(offset), label)
    local subtree_begin = offset

    local has_partitions = tvb(offset, 1):uint()
    offset = offset + 1
    if has_partitions > 0 then
        offset = sequence_deserialize(tvb, offset, encoding, subtree, "partitions", string_deserialize)
    end

    offset = optional_deserialize(tvb, offset, encoding, subtree, "group_data:", sequence_octet_deserialize)

    subtree:set_len(offset - subtree_begin)

    return offset
end

local function OBJK_Publisher_Binary_deserialize(tvb, offset, encoding, tree, label)
    local subtree = tree:add(tvb(offset), label)
    local subtree_begin = offset

    offset = optional_deserialize(tvb, offset, encoding, subtree, "publisher_name:", string_deserialize)
    offset = optional_deserialize(tvb, offset, encoding, subtree, "qos", OBJK_Publisher_Binary_Qos_deserialize)

    subtree:set_len(offset - subtree_begin)

    return offset
end

local function OBJK_Subscriber_Binary_Qos_deserialize(tvb, offset, encoding, tree, label)
    local subtree = tree:add(tvb(offset), label)
    local subtree_begin = offset

    local has_partitions = tvb(offset, 1):uint()
    offset = offset + 1
    if has_partitions > 0 then
        offset = sequence_deserialize(tvb, offset, encoding, subtree, "partitions", string_deserialize)
    end

    offset = optional_deserialize(tvb, offset, encoding, subtree, "group_data:", sequence_octet_deserialize)

    subtree:set_len(offset - subtree_begin)

    return offset
end

local function OBJK_Subscriber_Binary_deserialize(tvb, offset, encoding, tree, label)
    local subtree = tree:add(tvb(offset), label)
    local subtree_begin = offset

    offset = optional_deserialize(tvb, offset, encoding, subtree, "subscriber_name:", string_deserialize)
    offset = optional_deserialize(tvb, offset, encoding, subtree, "qos", OBJK_Subscriber_Binary_Qos_deserialize)

    subtree:set_len(offset - subtree_begin)

    return offset
end

local function EndpointQosFlags_deserialize(tvb, offset, encoding, tree, label)
    offset = align(offset, 2)

    local flags = tvb_uint(tvb(offset, 2), encoding)
    local subtree = tree:add(tvb(offset, 2), label, string.format("0x%04X", flags))
    if bit.band(flags, 0x20) == 0x20 then
        subtree:append_text(", is_durability_persistent")
        subtree:add(tvb(offset, 2), ".... .... .... 1... = is_durability_persistent:", "Set")
    else
        subtree:add(tvb(offset, 2), ".... .... .... 0... = is_durability_persistent:", "Not set")
    end
    if bit.band(flags, 0x10) == 0x10 then
        subtree:append_text(", is_durability_transient")
        subtree:add(tvb(offset, 2), ".... .... .... 1... = is_durability_transient:", "Set")
    else
        subtree:add(tvb(offset, 2), ".... .... .... 0... = is_durability_transient:", "Not set")
    end
    if bit.band(flags, 0x08) == 0x08 then
        subtree:append_text(", is_durability_transient_local")
        subtree:add(tvb(offset, 2), ".... .... .... 1... = is_durability_transient_local:", "Set")
    else
        subtree:add(tvb(offset, 2), ".... .... .... 0... = is_durability_transient_local:", "Not set")
    end
    if bit.band(flags, 0x04) == 0x04 then
        subtree:append_text(", is_ownership_exclusive")
        subtree:add(tvb(offset, 2), ".... .... .... .1.. = is_ownership_exclusive:", "Set")
    else
        subtree:add(tvb(offset, 2), ".... .... .... .0.. = is_ownership_exclusive:", "Not set")
    end
    if bit.band(flags, 0x02) == 0x02 then
        subtree:append_text(", is_history_keep_all")
        subtree:add(tvb(offset, 2), ".... .... .... ..1. = is_history_keep_all:", "Set")
    else
        subtree:add(tvb(offset, 2), ".... .... .... ..0. = is_history_keep_all:", "Not set")
    end
    if bit.band(flags, 0x01) == 0x01 then
        subtree:append_text(", is_reliable")
        subtree:add(tvb(offset, 2), ".... .... .... ...1 = is_reliable:", "Set")
    else
        subtree:add(tvb(offset, 2), ".... .... .... ...0 = is_reliable:", "Not set")
    end
    offset = offset + 2

    return offset
end

local function OBJK_Endpoint_Binary_Qos_deserialize(tvb, offset, encoding, tree)
    offset = EndpointQosFlags_deserialize(tvb, offset, encoding, tree, "qos_flags:")
    offset = optional_deserialize(tvb, offset, encoding, tree, "history_depth:", unsigned_short_deserialize)
    offset = optional_deserialize(tvb, offset, encoding, tree, "deadline_msec:", unsigned_long_deserialize)
    offset = optional_deserialize(tvb, offset, encoding, tree, "lifespan_msec:", unsigned_long_deserialize)
    offset = optional_deserialize(tvb, offset, encoding, tree, "user_data:", sequence_octet_deserialize)

    return offset
end

local function OBJK_DataWriter_Binary_Qos_deserialize(tvb, offset, encoding, tree, label)
    local subtree = tree:add(tvb(offset), label)
    local subtree_begin = offset

    offset = OBJK_Endpoint_Binary_Qos_deserialize(tvb, offset, encoding, subtree)
    -- WARNING: This is `@optional unsigned long ownership_strength;` in the official dds_xrce_types.idl.
    offset = optional_deserialize(tvb, offset, encoding, tree, "ownership_strength:", unsigned_long_long_deserialize)

    subtree:set_len(offset - subtree_begin)

    return offset
end

local function OBJK_DataReader_Binary_Qos_deserialize(tvb, offset, encoding, tree, label)
    local subtree = tree:add(tvb(offset), label)
    local subtree_begin = offset

    offset = OBJK_Endpoint_Binary_Qos_deserialize(tvb, offset, encoding, subtree)
    -- WARNING: This is `@optional unsigned long timebasedfilter_msec;` in the official dds_xrce_types.idl.
    offset = optional_deserialize(tvb, offset, encoding, tree, "timebasedfilter_msec:", unsigned_long_long_deserialize)
    offset = optional_deserialize(tvb, offset, encoding, tree, "contentbased_filter:", string_deserialize)

    subtree:set_len(offset - subtree_begin)

    return offset
end

local function OBJK_DataReader_Binary_deserialize(tvb, offset, encoding, tree, label)
    local subtree = tree:add(tvb(offset), label)
    local subtree_begin = offset

    -- WARNING: This is `@optional string topic_nmne;` in the official dds_xrce_types.idl.
    if track_objects then
        -- Register the topic name for this object.
        topic_id = tvb(offset, 2):uint()
        if object_topic_names[topic_id] ~= nil then
            object_topic_names[object_id] = object_topic_names[topic_id]
        end
    end
    offset = ObjectId_deserialize(tvb, offset, encoding, subtree, "topic_id:")

    offset = optional_deserialize(tvb, offset, encoding, subtree, "qos", OBJK_DataReader_Binary_Qos_deserialize)

    subtree:set_len(offset - subtree_begin)

    return offset
end

local function OBJK_DataWriter_Binary_deserialize(tvb, offset, encoding, tree, label)
    local subtree = tree:add(tvb(offset), label)
    local subtree_begin = offset

    -- WARNING: This is `@optional string topic_name;` in the official dds_xrce_types.idl.
    if track_objects then
        -- Register the topic name for this object.
        topic_id = tvb(offset, 2):uint()
        if object_topic_names[topic_id] ~= nil then
            object_topic_names[object_id] = object_topic_names[topic_id]
        end
    end
    offset = ObjectId_deserialize(tvb, offset, encoding, subtree, "topic_id:")

    offset = optional_deserialize(tvb, offset, encoding, subtree, "qos", OBJK_DataWriter_Binary_Qos_deserialize)

    subtree:set_len(offset - subtree_begin)

    return offset
end

local function OBJK_Representation3Formats_deserialize(tvb, offset, encoding, tree, label)
    local subtree = tree:add(tvb(offset), label)
    local subtree_begin = offset

    local format = tvb(offset, 1):uint()
    local t_format = subtree:add(tvb(offset, 1), "format:", string.format("0x%02X", format))
    offset = offset + 1

    if format == 0x01 then
        --- REPRESENTATION_BY_REFERENCE
        t_format:append_text(" (REPRESENTATION_BY_REFERENCE)")
        offset = align(offset, 4)
        local size = tvb_uint(tvb(offset, 4), encoding)
        offset = offset + 4
        local object_reference = tvb(offset, size):stringz()
        subtree:add(tvb(offset, size), "object_reference:", object_reference)
        offset = offset + size
        if track_objects then
            -- Register the profile and topic names for this object.
            object_profile_names[object_id] = object_reference
            local topic_name = nil
            if bit.band(object_id, 0x0F) == 0x2 then
                -- OBJK_TOPIC
                topic_name = topic_names[object_reference]
            elseif bit.band(object_id, 0x0F) == 0x5 then
                -- OBJK_DATAWRITER
                topic_name = data_writer_topic_names[object_reference]
            elseif bit.band(object_id, 0x0F) == 0x6 then
                -- OBJK_DATAREADER
                topic_name = data_reader_topic_names[object_reference]
            end
            if topic_name ~= nil then
                object_topic_names[object_id] = topic_name
            end
        end
    elseif format == 0x02 then
        --- REPRESENTATION_AS_XML_STRING
        t_format:append_text(" (REPRESENTATION_AS_XML_STRING)")
        offset = align(offset, 4)
        local size = tvb_uint(tvb(offset, 4), encoding)
        offset = offset + 4
        local xml_string_representation = tvb(offset, size):stringz()
        subtree:add(tvb(offset, size), "xml_string_representation:", xml_string_representation)
        offset = offset + size
        if track_objects then
            -- Register the profile, topic and type names for this object.
            local profile_name = string.match(xml_string_representation, XML_PROFILE_NAME_PATTERN)
            if profile_name ~= nil then
                object_profile_names[object_id] = profile_name
            end
            local topic_name = nil
            if bit.band(object_id, 0x0F) == 0x2 then
                -- OBJK_TOPIC
                topic_name = string.match(xml_string_representation, XML_NAME_PATTERN)
                local type_name = string.match(xml_string_representation, XML_DATA_TYPE_PATTERN)
                if topic_name ~= nil and type_name ~= nil then
                    topic_type_names[topic_name] = type_name
                end
            elseif bit.band(object_id, 0x0F) == 0x5 then
                -- OBJK_DATAWRITER
                topic_name = string.match(xml_string_representation, XML_NAME_PATTERN)
            elseif bit.band(object_id, 0x0F) == 0x6 then
                -- OBJK_DATAREADER
                topic_name = string.match(xml_string_representation, XML_NAME_PATTERN)
            end
            if topic_name ~= nil then
                object_topic_names[object_id] = topic_name
            end
        end
    elseif format == 0x03 then
        --- REPRESENTATION_IN_BINARY
        t_format:append_text(" (REPRESENTATION_IN_BINARY)")

        offset = align(offset, 4)
        local size = tvb_uint(tvb(offset, 4), encoding)
        offset = offset + 4
        if bit.band(object_id, 0x0F) == 0x1 then
            -- OBJK_PARTICIPANT
            OBJK_DomainParticipant_Binary_deserialize(
                tvb(offset, size):tvb(),
                0,
                encoding,
                subtree,
                "binary_representation"
            )
        elseif bit.band(object_id, 0x0F) == 0x2 then
            -- OBJK_TOPIC
            OBJK_Topic_Binary_deserialize(tvb(offset, size):tvb(), 0, encoding, subtree, "binary_representation")
        elseif bit.band(object_id, 0x0F) == 0x3 then
            -- OBJK_PUBLISHER
            OBJK_Publisher_Binary_deserialize(tvb(offset, size):tvb(), 0, encoding, subtree, "binary_representation")
        elseif bit.band(object_id, 0x0F) == 0x4 then
            -- OBJK_SUBSCRIBER
            OBJK_Subscriber_Binary_deserialize(tvb(offset, size):tvb(), 0, encoding, subtree, "binary_representation")
        elseif bit.band(object_id, 0x0F) == 0x5 then
            -- OBJK_DATAWRITER
            OBJK_DataWriter_Binary_deserialize(tvb(offset, size):tvb(), 0, encoding, subtree, "binary_representation")
        elseif bit.band(object_id, 0x0F) == 0x6 then
            -- OBJK_DATAREADER
            OBJK_DataReader_Binary_deserialize(tvb(offset, size):tvb(), 0, encoding, subtree, "binary_representation")
        else
            subtree:add(tvb(offset, size), "binary_representation:", tvb(offset, size):bytes():tohex(true, " "))
        end
        offset = offset + size
    end

    subtree:set_len(offset - subtree_begin)

    return offset
end

local function OBJK_Representation3_Base(tvb, offset, encoding, tree)
    return OBJK_Representation3Formats_deserialize(tvb, offset, encoding, tree, "representation")
end

local function OBJK_QOSPROFILE_Representation_deserialize(tvb, offset, encoding, tree, label)
    local subtree = tree:add(tvb(offset), label)
    local subtree_begin = offset

    offset = OBJK_Representation3_Base(tvb, offset, encoding, subtree)

    subtree:set_len(offset - subtree_begin)

    return offset
end

local function OBJK_TYPE_Representation_deserialize(tvb, offset, encoding, tree, label)
    local subtree = tree:add(tvb(offset), label)
    local subtree_begin = offset

    offset = OBJK_Representation3_Base(tvb, offset, encoding, subtree)

    subtree:set_len(offset - subtree_begin)

    return offset
end

local function OBJK_DOMAIN_Representation_deserialize(tvb, offset, encoding, tree, label)
    local subtree = tree:add(tvb(offset), label)
    local subtree_begin = offset

    offset = OBJK_Representation3_Base(tvb, offset, encoding, subtree)

    subtree:set_len(offset - subtree_begin)

    return offset
end

local function OBJK_APPLICATION_Representation_deserialize(tvb, offset, encoding, tree, label)
    local subtree = tree:add(tvb(offset), label)
    local subtree_begin = offset

    offset = OBJK_Representation3_Base(tvb, offset, encoding, subtree)

    subtree:set_len(offset - subtree_begin)

    return offset
end

local function OBJK_PUBLISHER_Representation_deserialize(tvb, offset, encoding, tree, label)
    local subtree = tree:add(tvb(offset), label)
    local subtree_begin = offset

    offset = OBJK_Representation3_Base(tvb, offset, encoding, subtree)
    offset = ObjectId_deserialize(tvb, offset, encoding, subtree, "participant_id:")

    subtree:set_len(offset - subtree_begin)

    return offset
end

local function OBJK_SUBSCRIBER_Representation_deserialize(tvb, offset, encoding, tree, label)
    local subtree = tree:add(tvb(offset), label)
    local subtree_begin = offset

    offset = OBJK_Representation3_Base(tvb, offset, encoding, subtree)
    offset = ObjectId_deserialize(tvb, offset, encoding, subtree, "participant_id:")

    subtree:set_len(offset - subtree_begin)

    return offset
end

local function DATAWRITER_Representation_deserialize(tvb, offset, encoding, tree, label)
    local subtree = tree:add(tvb(offset), label)
    local subtree_begin = offset

    offset = OBJK_Representation3_Base(tvb, offset, encoding, subtree)
    offset = ObjectId_deserialize(tvb, offset, encoding, subtree, "publisher_id:")

    subtree:set_len(offset - subtree_begin)

    return offset
end

local function DATAREADER_Representation_deserialize(tvb, offset, encoding, tree, label)
    local subtree = tree:add(tvb(offset), label)
    local subtree_begin = offset

    offset = OBJK_Representation3_Base(tvb, offset, encoding, subtree)
    offset = ObjectId_deserialize(tvb, offset, encoding, subtree, "subscriber_id:")

    subtree:set_len(offset - subtree_begin)

    return offset
end

local function OBJK_PARTICIPANT_Representation_deserialize(tvb, offset, encoding, tree, label)
    local subtree = tree:add(tvb(offset), label)
    local subtree_begin = offset

    offset = OBJK_Representation3_Base(tvb, offset, encoding, subtree)
    offset = short_deserialize(tvb, offset, encoding, subtree, "domain_id:")

    subtree:set_len(offset - subtree_begin)

    return offset
end

local function OBJK_TOPIC_Representation_deserialize(tvb, offset, encoding, tree, label)
    local subtree = tree:add(tvb(offset), label)
    local subtree_begin = offset

    offset = OBJK_Representation3_Base(tvb, offset, encoding, subtree)
    offset = ObjectId_deserialize(tvb, offset, encoding, subtree, "participant_id:")

    subtree:set_len(offset - subtree_begin)

    return offset
end

local function ObjectVariant_deserialize(tvb, offset, encoding, tree, label)
    local subtree = tree:add(tvb(offset), label)
    local subtree_begin = offset

    local kind = tvb(offset, 1):uint()
    local t_kind = subtree:add(tvb(offset, 1), "kind:", string.format("0x%02X", kind))
    offset = offset + 1

    if kind == 0x0D then
        -- OBJK_AGENT
        t_kind:append_text(" (OBJK_AGENT)")
        offset = AGENT_Representation_deserialize(tvb, offset, encoding, subtree, "agent")
    elseif kind == 0x0E then
        -- OBJK_CLIENT
        t_kind:append_text(" (OBJK_CLIENT)")
        offset = CLIENT_Representation_deserialize(tvb, offset, encoding, subtree, "client")
    elseif kind == 0x0C then
        -- OBJK_APPLICATION
        t_kind:append_text(" (OBJK_APPLICATION)")
        offset = OBJK_APPLICATION_Representation_deserialize(tvb, offset, encoding, subtree, "application")
    elseif kind == 0x01 then
        -- OBJK_PARTICIPANT
        t_kind:append_text(" (OBJK_PARTICIPANT)")
        offset = OBJK_PARTICIPANT_Representation_deserialize(tvb, offset, encoding, subtree, "participant")
    elseif kind == 0x0B then
        -- OBJK_QOSPROFILE
        t_kind:append_text(" (OBJK_QOSPROFILE)")
        offset = OBJK_QOSPROFILE_Representation_deserialize(tvb, offset, encoding, subtree, "qos_profile")
    elseif kind == 0x0A then
        -- OBJK_TYPE
        t_kind:append_text(" (OBJK_TYPE)")
        offset = OBJK_TYPE_Representation_deserialize(tvb, offset, encoding, subtree, "type")
    elseif kind == 0x02 then
        -- OBJK_TOPIC
        t_kind:append_text(" (OBJK_TOPIC)")
        offset = OBJK_TOPIC_Representation_deserialize(tvb, offset, encoding, subtree, "topic")
    elseif kind == 0x03 then
        -- OBJK_PUBLISHER
        t_kind:append_text(" (OBJK_PUBLISHER)")
        offset = OBJK_PUBLISHER_Representation_deserialize(tvb, offset, encoding, subtree, "publisher")
    elseif kind == 0x04 then
        -- OBJK_SUBSCRIBER
        t_kind:append_text(" (OBJK_SUBSCRIBER)")
        offset = OBJK_SUBSCRIBER_Representation_deserialize(tvb, offset, encoding, subtree, "subscriber")
    elseif kind == 0x05 then
        -- OBJK_DATAWRITER
        t_kind:append_text(" (OBJK_DATAWRITER)")
        offset = DATAWRITER_Representation_deserialize(tvb, offset, encoding, subtree, "data_writer")
    elseif kind == 0x06 then
        -- OBJK_DATAREADER
        t_kind:append_text(" (OBJK_DATAREADER)")
        offset = DATAREADER_Representation_deserialize(tvb, offset, encoding, subtree, "data_reader")
    end

    subtree:set_len(offset - subtree_begin)

    return offset
end

local function RequestId_deserialize(tvb, offset, encoding, tree, label)
    tree:add(tvb(offset, 2), label, tvb(offset, 2):bytes():tohex(true))
    offset = offset + 2

    return offset
end

local function StatusValue_deserialize(tvb, offset, encoding, tree, label)
    local status = tvb(offset, 1):uint()
    local subtree = tree:add(tvb(offset, 1), "status:", string.format("0x%02X", status))
    if status == 0x00 then
        subtree:append_text(" (STATUS_OK)")
    elseif status == 0x01 then
        subtree:append_text(" (STATUS_OK_MATCHED)")
    elseif status == 0x80 then
        subtree:append_text(" (STATUS_ERR_DDS_ERROR)")
    elseif status == 0x81 then
        subtree:append_text(" (STATUS_ERR_MISMATCH)")
    elseif status == 0x82 then
        subtree:append_text(" (STATUS_ERR_ALREADY_EXISTS)")
    elseif status == 0x83 then
        subtree:append_text(" (STATUS_ERR_DENIED)")
    elseif status == 0x84 then
        subtree:append_text(" (STATUS_ERR_UNKNOWN_REFERENEC)")
    elseif status == 0x85 then
        subtree:append_text(" (STATUS_ERR_INVALID_DATA)")
    elseif status == 0x86 then
        subtree:append_text(" (STATUS_ERR_INCOMPATIBLE)")
    elseif status == 0x87 then
        subtree:append_text(" (STATUS_ERR_RESOURCES)")
    end
    offset = offset + 1

    return offset
end

local function ResultStatus_deserialize(tvb, offset, encoding, tree, label)
    local subtree = tree:add(tvb(offset), label)
    local subtree_begin = offset

    offset = StatusValue_deserialize(tvb, offset, encoding, subtree, "status:")
    offset = octet_deserialize(tvb, offset, encoding, subtree, "implementation_status:")

    subtree:set_len(offset - subtree_begin)

    return offset
end

local function InfoMask_deserialize(tvb, offset, encoding, tree, label)
    local info_mask = tvb_uint(tvb(offset, 4), encoding)
    local subtree = tree:add(tvb(offset, 4), label, string.format("0x%08X", info_mask))
    if bit.band(info_mask, 0x2) == 0x2 then
        subtree:append_text(", INFO_ACTIVITY")
        subtree:add(tvb(offset, 4), ".... .... .... .... .... .... .... ..1. = INFO_ACTIVITY:", "Set")
    else
        subtree:add(tvb(offset, 4), ".... .... .... .... .... .... .... ..0. = INFO_ACTIVITY:", "Not set")
    end
    if bit.band(info_mask, 0x1) == 0x1 then
        subtree:append_text(", INFO_CONFIGURATION")
        subtree:add(tvb(offset, 4), ".... .... .... .... .... .... .... ...1 = INFO_CONFIGURATION:", "Set")
    else
        subtree:add(tvb(offset, 4), ".... .... .... .... .... .... .... ...0 = INFO_CONFIGURATION:", "Not set")
    end
    offset = offset + 4

    return offset
end

local function AGENT_ActivityInfo_deserialize(tvb, offset, encoding, tree, label)
    local subtree = tree:add(tvb(offset), label)
    local subtree_begin = offset

    offset = short_deserialize(tvb, offset, encoding, subtree, "availability:")
    offset = TransportLocatorSeq_deserialize(tvb, offset, encoding, subtree, "address_seq")

    subtree:set_len(offset - subtree_begin)

    return offset
end

local function DATAREADER_ActivityInfo_deserialize(tvb, offset, encoding, tree, label)
    offset = align(offset, 2)

    local subtree = tree:add(tvb(offset, 2), label)

    return short_deserialize(tvb, offset, encoding, subtree, "highest_acked_num:")
end

local function DATAWRITER_ActivityInfo_deserialize(tvb, offset, encoding, tree, label)
    offset = align(offset, 8)

    local subtree = tree:add(tvb(offset, 10), label)

    offset = unsigned_long_long_deserialize(tvb, offset, encoding, subtree, "sample_seq_num:")
    offset = short_deserialize(tvb, offset, encoding, subtree, "stream_seq_num:")

    return offset
end

local function ActivityInfoVariant_deserialize(tvb, offset, encoding, tree, label)
    local subtree = tree:add(tvb(offset), label)
    local subtree_begin = offset

    local kind = tvb(offset, 1):uint()
    local t_kind = subtree:add(tvb(offset, 1), "kind:", string.format("0x%02X", kind))
    offset = offset + 1

    if kind == 0x0D then
        -- OBJK_AGENT
        t_kind:append_text(" (OBJK_AGENT)")
        offset = AGENT_ActivityInfo_deserialize(tvb, offset, encoding, subtree, "agent")
    elseif kind == 0x05 then
        -- OBJK_DATAWRITER
        t_kind:append_text(" (OBJK_DATAWRITER)")
        offset = DATAWRITER_ActivityInfo_deserialize(tvb, offset, encoding, subtree, "data_writer")
    elseif kind == 0x06 then
        -- OBJK_DATAREADER
        t_kind:append_text(" (OBJK_DATAREADER)")
        offset = DATAREADER_ActivityInfo_deserialize(tvb, offset, encoding, subtree, "data_reader")
    end

    subtree:set_len(offset - subtree_begin)

    return offset
end

local function ObjectInfo_deserialize(tvb, offset, encoding, tree, label)
    local subtree = tree:add(tvb(offset), label)
    local subtree_begin = offset

    -- WARNING: The config member comes after the activity member in the official dds_xrce_types.idl.
    offset = optional_deserialize(tvb, offset, encoding, subtree, "config", ObjectVariant_deserialize)
    offset = optional_deserialize(tvb, offset, encoding, subtree, "activity", ActivityInfoVariant_deserialize)

    subtree:set_len(offset - subtree_begin)

    return offset
end

local function BaseObjectRequest_deserialize(tvb, offset, encoding, tree)
    offset = RequestId_deserialize(tvb, offset, encoding, tree, "request_id:")
    object_id = tvb(offset, 2):uint()
    offset = ObjectId_deserialize(tvb, offset, encoding, tree, "object_id:")

    return offset
end

local function RelatedObjectRequest_deserialize(tvb, offset, encoding, tree, label)
    local subtree = tree:add(tvb(offset), label)
    local subtree_begin = offset

    offset = BaseObjectRequest_deserialize(tvb, offset, encoding, subtree)

    subtree:set_len(offset - subtree_begin)

    return offset
end

local function BaseObjectReply_deserialize(tvb, offset, encoding, tree)
    offset = RelatedObjectRequest_deserialize(tvb, offset, encoding, tree, "related_request")
    offset = ResultStatus_deserialize(tvb, offset, encoding, tree, "result")

    return offset
end

local function DataFormat_deserialize(tvb, offset, encoding, tree, label)
    local data_format = tvb(offset, 1):uint()
    local subtree = tree:add(tvb(offset, 1), label, string.format("0x%02X", data_format))
    if data_format == 0x00 then
        subtree:append_text(" (FORMAT_DATA)")
    elseif data_format == 0x02 then
        subtree:append_text(" (FORMAT_SAMPLE)")
    elseif data_format == 0x08 then
        subtree:append_text(" (FORMAT_DATA_SRQ)")
    elseif data_format == 0x0A then
        subtree:append_text(" (FORMAT_SAMPLE_SEQ)")
    elseif data_format == 0x0E then
        subtree:append_text(" (FORMAT_PACKED_SAMPLES)")
    end
    offset = offset + 1

    return offset
end

local function DataDeliveryControl_deserialize(tvb, offset, encoding, tree, label)
    offset = align(offset, 2)

    local subtree = tree:add(tvb(offset, 8), label)

    offset = unsigned_short_deserialize(tvb, offset, encoding, subtree, "max_samples:")
    offset = unsigned_short_deserialize(tvb, offset, encoding, subtree, "max_elapsed_time:")
    offset = unsigned_short_deserialize(tvb, offset, encoding, subtree, "max_bytes_per_second:")
    offset = unsigned_short_deserialize(tvb, offset, encoding, subtree, "min_pace_period:")

    return offset
end

local function ReadSpecification_deserialize(tvb, offset, encoding, tree, label)
    local subtree = tree:add(tvb(offset), label)
    local subtree_begin = offset

    offset = StreamId_deserialize(tvb, offset, encoding, subtree, "preferred_stream_id:")
    offset = DataFormat_deserialize(tvb, offset, encoding, subtree, "data_format:")
    offset = optional_deserialize(tvb, offset, encoding, subtree, "content_filter_expression:", string_deserialize)
    offset = optional_deserialize(tvb, offset, encoding, subtree, "delivery_control", DataDeliveryControl_deserialize)

    subtree:set_len(offset - subtree_begin)

    return offset
end

local function SampleInfoFlags_deserialize(tvb, offset, encoding, tree, label)
    local flags = tvb(offset, 1):uint()
    local subtree = tree:add(tvb(offset, 1), label, string.format("0x%02X", flags))
    if bit.band(flags, 0x8) == 0x8 then
        subtree:append_text(", SAMPLE_STATE_READ")
        subtree:add(tvb(offset, 1), ".... 1... = SAMPLE_STATE_READ:", "Set")
    else
        subtree:add(tvb(offset, 1), ".... 0... = SAMPLE_STATE_READ:", "Not set")
    end
    if bit.band(flags, 0x4) == 0x4 then
        subtree:append_text(", VIEW_STATE_NEW")
        subtree:add(tvb(offset, 1), ".... .1.. = VIEW_STATE_NEW:", "Set")
    else
        subtree:add(tvb(offset, 1), ".... .0.. = VIEW_STATE_NEW:", "Not set")
    end
    if bit.band(flags, 0x2) == 0x2 then
        subtree:append_text(", INSTANCE_STATE_DISPOSED")
        subtree:add(tvb(offset, 1), ".... ..1. = INSTANCE_STATE_DISPOSED:", "Set")
    else
        subtree:add(tvb(offset, 1), ".... ..0. = INSTANCE_STATE_DISPOSED:", "Not set")
    end
    if bit.band(flags, 0x1) == 0x1 then
        subtree:append_text(", INSTANCE_STATE_UNREGISTERED")
        subtree:add(tvb(offset, 1), ".... ...1 = INSTANCE_STATE_UNREGISTERED:", "Set")
    else
        subtree:add(tvb(offset, 1), ".... ...0 = INSTANCE_STATE_UNREGISTERED:", "Not set")
    end
    offset = offset + 1

    return offset
end

local function SeqNumberAndTimestamp_deserialize(tvb, offset, encoding, tree, label)
    offset = align(offset, 4)

    local subtree = tree:add(tvb(offset, 8), label)

    offset = unsigned_long_deserialize(tvb, offset, encoding, subtree, "sequence_number:")
    offset = unsigned_long_deserialize(tvb, offset, encoding, subtree, "session_time_offset:")

    return offset
end

local function SampleInfoDetail_deserialize(tvb, offset, encoding, tree, label)
    local subtree = tree:add(tvb(offset), label)
    local subtree_begin = offset

    local format = tvb(offset, 1):uint()
    local t_format = subtree:add(tvb(offset, 1), "format:", string.format("0x%02X", format))
    offset = offset + 1
    if format == 0x00 then
        -- FORMAT_EMPTY
        t_format:append_text(" (FORMAT_EMPTY)")
    elseif format == 0x01 then
        -- FORMAT_SEQNUM
        t_format:append_text(" (FORMAT_SEQNUM)")
        offset = unsigned_long_deserialize(tvb, offset, encoding, subtree, "sequence_number:")
    elseif format == 0x02 then
        -- FORMAT_TIMESTAMP
        t_format:append_text(" (FORMAT_TIMESTAMP)")
        offset = unsigned_long_deserialize(tvb, offset, encoding, subtree, "session_time_offset:")
    elseif format == 0x03 then
        -- FORMAT_SEQN_TIMS
        t_format:append_text(" (FORMAT_SEQN_TIMS)")
        offset = SeqNumberAndTimestamp_deserialize(tvb, offset, encoding, subtree, "seqnum_n_timestamp")
    end

    subtree:set_len(offset - subtree_begin)

    return offset
end

local function SampleInfo_deserialize(tvb, offset, encoding, tree, label)
    local subtree = tree:add(tvb(offset), label)
    local subtree_begin = offset

    offset = SampleInfoFlags_deserialize(tvb, offset, encoding, subtree, "state:")
    offset = SampleInfoDetail_deserialize(tvb, offset, encoding, subtree, "detail")

    subtree:set_len(offset - subtree_begin)

    return offset
end

local function SampleInfoDelta_deserialize(tvb, offset, encoding, tree, label)
    local subtree = tree:add(tvb(offset), label)
    local subtree_begin = offset

    offset = SampleInfoFlags_deserialize(tvb, offset, encoding, subtree, "state:")
    offset = octet_deserialize(tvb, offset, encoding, subtree, "seq_number_delta:")
    offset = unsigned_short_deserialize(tvb, offset, encoding, subtree, "timestamp_delta:")

    subtree:set_len(offset - subtree_begin)

    return offset
end

local function SampleData_deserialize(tvb, offset, encoding, tree, label)
    local type_name = object_type_names[object_id]
    if type_name == nil and track_objects then
        local topic_name = object_topic_names[object_id]
        if topic_name ~= nil then
            type_name = topic_type_names[topic_name]
        end
    end

    local subtree = tree:add(tvb(offset), label)
    if deserialize_types and type_name ~= nil and types[type_name] ~= nil then
        types[type_name](tvb(offset):tvb(), 0, encoding, subtree, "serialized_data (" .. type_name .. ")")
    else
        subtree:add(tvb(offset), "serialized_data:", tvb(offset):bytes():tohex(true, " "))
    end
    offset = tvb:len()

    return offset
end

local function SampleDataSeq_deserialize(tvb, offset, encoding, tree, label)
    offset = align(offset, 4)

    local subtree = tree:add(tvb(offset), label)
    local subtree_begin = offset

    local size = tvb_uint(tvb(offset, 4), encoding)
    offset = offset + 4
    if size == 0 then
        subtree:append_text(" [empty]")
    else
        local sample_data_size = math.ceil((tvb:len() - offset) / size)
        for i = 1, size do
            offset =
                SampleData_deserialize(
                tvb(0, offset + sample_data_size),
                offset,
                encoding,
                subtree,
                "[" .. tostring(i - 1) .. "]"
            )
        end
    end

    subtree:set_len(offset - subtree_begin)

    return offset
end

local function Sample_deserialize(tvb, offset, encoding, tree, label)
    local subtree = tree:add(tvb(offset), label)
    local subtree_begin = offset

    offset = SampleInfo_deserialize(tvb, offset, encoding, subtree, "info")
    offset = SampleData_deserialize(tvb, offset, encoding, subtree, "data")

    subtree:set_len(offset - subtree_begin)

    return offset
end

local function SampleSeq_deserialize(tvb, offset, encoding, tree, label)
    offset = align(offset, 4)

    local subtree = tree:add(tvb(offset), label)
    local subtree_begin = offset

    local size = tvb_uint(tvb(offset, 4), encoding)
    offset = offset + 4
    if size == 0 then
        subtree:append_text(" [empty]")
    else
        local sample_size = math.ceil((tvb:len() - offset) / size)
        for i = 1, size do
            offset =
                Sample_deserialize(
                tvb(0, offset + sample_size),
                offset,
                encoding,
                subtree,
                "[" .. tostring(i - 1) .. "]"
            )
        end
    end

    subtree:set_len(offset - subtree_begin)

    return offset
end

local function SampleDelta_deserialize(tvb, offset, encoding, tree, label)
    local subtree = tree:add(tvb(offset), label)
    local subtree_begin = offset

    offset = SampleInfoDelta_deserialize(tvb, offset, encoding, subtree, "info_delta")
    offset = SampleData_deserialize(tvb, offset, encoding, subtree, "data")

    subtree:set_len(offset - subtree_begin)

    return offset
end

local function PackedSamples_deserialize(tvb, offset, encoding, tree, label)
    local subtree = tree:add(tvb(offset), label)
    local subtree_begin = offset

    offset = SampleInfo_deserialize(tvb, offset, encoding, subtree, "info")

    offset = align(offset, 4)

    local t_sample_delta_seq = tree:add(tvb(offset), "sample_delta_seq")
    local sample_delta_seq_begin = offset

    local size = tvb_uint(tvb(offset, 4), encoding)
    offset = offset + 4
    if size == 0 then
        t_sample_delta_seq:append_text(" [empty]")
    else
        local sample_delta_size = math.ceil((tvb:len() - offset) / size)
        for i = 1, size do
            offset =
                SampleDelta_deserialize(
                tvb(0, offset + sample_delta_size),
                offset,
                encoding,
                t_sample_delta_seq,
                "[" .. tostring(i - 1) .. "]"
            )
        end
    end

    t_sample_delta_seq:set_len(offset - sample_delta_seq_begin)

    subtree:set_len(offset - subtree_begin)

    return offset
end

local function CREATE_CLIENT_Payload_deserialize(tvb, offset, encoding, tree, label)
    local subtree = tree:add(tvb(offset), label)

    return CLIENT_Representation_deserialize(tvb, offset, encoding, subtree, "client_representation")
end
dds_xrce_types["CREATE_CLIENT_Payload"] = CREATE_CLIENT_Payload_deserialize

local function CREATE_Payload_deserialize(tvb, offset, encoding, tree, label)
    local subtree = tree:add(tvb(offset), label)

    offset = BaseObjectRequest_deserialize(tvb, offset, encoding, subtree)
    offset = ObjectVariant_deserialize(tvb, offset, encoding, subtree, "object_representation")

    return offset
end
dds_xrce_types["CREATE_Payload"] = CREATE_Payload_deserialize

local function GET_INFO_Payload_deserialize(tvb, offset, encoding, tree, label)
    local subtree = tree:add(tvb(offset), label)

    offset = BaseObjectRequest_deserialize(tvb, offset, encoding, subtree)
    offset = InfoMask_deserialize(tvb, offset, encoding, subtree, "info_mask:")

    return offset
end
dds_xrce_types["GET_INFO_Payload"] = GET_INFO_Payload_deserialize

local function DELETE_Payload_deserialize(tvb, offset, encoding, tree, label)
    local subtree = tree:add(tvb(offset), label)

    return BaseObjectRequest_deserialize(tvb, offset, encoding, subtree)
end
dds_xrce_types["DELETE_Payload"] = DELETE_Payload_deserialize

local function STATUS_AGENT_Payload_deserialize(tvb, offset, encoding, tree, label)
    local subtree = tree:add(tvb(offset), label)

    -- WARNING: The result member is not present in the official dds_xrce_types.idl.
    offset = ResultStatus_deserialize(tvb, offset, encoding, subtree, "result")
    offset = AGENT_Representation_deserialize(tvb, offset, encoding, subtree, "agent_info")

    return offset
end
dds_xrce_types["STATUS_AGENT_Payload"] = STATUS_AGENT_Payload_deserialize

local function STATUS_Payload_deserialize(tvb, offset, encoding, tree, label)
    local subtree = tree:add(tvb(offset), label)

    return BaseObjectReply_deserialize(tvb, offset, encoding, subtree)
end
dds_xrce_types["STATUS_Payload"] = STATUS_Payload_deserialize

local function INFO_Payload_deserialize(tvb, offset, encoding, tree, label)
    local subtree = tree:add(tvb(offset), label)

    offset = BaseObjectReply_deserialize(tvb, offset, encoding, subtree)
    offset = ObjectInfo_deserialize(tvb, offset, encoding, subtree, "object_info")

    return offset
end
dds_xrce_types["INFO_Payload"] = INFO_Payload_deserialize

local function READ_DATA_Payload_deserialize(tvb, offset, encoding, tree, label)
    local subtree = tree:add(tvb(offset), label)

    offset = BaseObjectRequest_deserialize(tvb, offset, encoding, subtree)
    offset = ReadSpecification_deserialize(tvb, offset, encoding, subtree, "read_specification")

    return offset
end
dds_xrce_types["READ_DATA_Payload"] = READ_DATA_Payload_deserialize

local function WRITE_DATA_Payload_Data_deserialize(tvb, offset, encoding, tree, label)
    local subtree = tree:add(tvb(offset), label)

    offset = BaseObjectRequest_deserialize(tvb, offset, encoding, subtree)
    offset = SampleData_deserialize(tvb, offset, encoding, subtree, "data")

    return offset
end
dds_xrce_types["WRITE_DATA_Payload_Data"] = WRITE_DATA_Payload_Data_deserialize

local function WRITE_DATA_Payload_Sample_deserialize(tvb, offset, encoding, tree, label)
    local subtree = tree:add(tvb(offset), label)

    offset = BaseObjectRequest_deserialize(tvb, offset, encoding, subtree)
    offset = Sample_deserialize(tvb, offset, encoding, subtree, "sample")

    return offset
end
dds_xrce_types["WRITE_DATA_Payload_Sample"] = WRITE_DATA_Payload_Sample_deserialize

local function WRITE_DATA_Payload_DataSeq_deserialize(tvb, offset, encoding, tree, label)
    local subtree = tree:add(tvb(offset), label)

    offset = BaseObjectRequest_deserialize(tvb, offset, encoding, subtree)
    offset = SampleDataSeq_deserialize(tvb, offset, encoding, subtree, "data_seq")

    return offset
end
dds_xrce_types["WRITE_DATA_Payload_DataSeq"] = WRITE_DATA_Payload_DataSeq

local function WRITE_DATA_Payload_SampleSeq_deserialize(tvb, offset, encoding, tree, label)
    local subtree = tree:add(tvb(offset), label)

    offset = BaseObjectRequest_deserialize(tvb, offset, encoding, subtree)
    offset = SampleSeq_deserialize(tvb, offset, encoding, subtree, "sample_seq")

    return offset
end
dds_xrce_types["WRITE_DATA_Payload_SampleSeq"] = WRITE_DATA_Payload_SampleSeq_deserialize

local function WRITE_DATA_Payload_PackedSamples_deserialize(tvb, offset, encoding, tree, label)
    local subtree = tree:add(tvb(offset), label)

    offset = BaseObjectRequest_deserialize(tvb, offset, encoding, subtree)
    offset = PackedSamples_deserialize(tvb, offset, encoding, subtree, "packed_samples")

    return offset
end
dds_xrce_types["WRITE_DATA_Payload_PackedSamples"] = WRITE_DATA_Payload_PackedSamples_deserialize

local function DATA_Payload_Data_deserialize(tvb, offset, encoding, tree, label)
    local subtree = tree:add(tvb(offset), label)

    offset = BaseObjectRequest_deserialize(tvb, offset, encoding, subtree)
    offset = SampleData_deserialize(tvb, offset, encoding, subtree, "data")

    return offset
end
dds_xrce_types["DATA_Payload_Data"] = DATA_Payload_Data_deserialize

local function DATA_Payload_Sample_deserialize(tvb, offset, encoding, tree, label)
    local subtree = tree:add(tvb(offset), label)

    offset = BaseObjectRequest_deserialize(tvb, offset, encoding, subtree)
    offset = Sample_deserialize(tvb, offset, encoding, subtree, "sample")

    return offset
end
dds_xrce_types["DATA_Payload_Sample"] = DATA_Payload_Sample_deserialize

local function DATA_Payload_DataSeq_deserialize(tvb, offset, encoding, tree, label)
    local subtree = tree:add(tvb(offset), label)

    offset = BaseObjectRequest_deserialize(tvb, offset, encoding, subtree)
    offset = SampleDataSeq_deserialize(tvb, offset, encoding, subtree, "data_seq")

    return offset
end
dds_xrce_types["DATA_Payload_DataSeq"] = DATA_Payload_DataSeq_deserialize

local function DATA_Payload_SampleSeq_deserialize(tvb, offset, encoding, tree, label)
    local subtree = tree:add(tvb(offset), label)

    offset = BaseObjectRequest_deserialize(tvb, offset, encoding, subtree)
    offset = SampleSeq_deserialize(tvb, offset, encoding, subtree, "sample_seq")

    return offset
end
dds_xrce_types["DATA_Payload_SampleSeq"] = DATA_Payload_SampleSeq_deserialize

local function DATA_Payload_PackedSamples_deserialize(tvb, offset, encoding, tree, label)
    local subtree = tree:add(tvb(offset), label)

    offset = BaseObjectRequest_deserialize(tvb, offset, encoding, subtree)
    offset = PackedSamples_deserialize(tvb, offset, encoding, subtree, "packed_samples")

    return offset
end
dds_xrce_types["DATA_Payload_PackedSamples"] = DATA_Payload_PackedSamples_deserialize

local function ACKNACK_Payload_deserialize(tvb, offset, encoding, tree, label)
    local subtree = tree:add(tvb(offset), label)

    offset = unsigned_short_deserialize(tvb, offset, encoding, subtree, "first_unacked_seq_num:")
    subtree:add(tvb(offset, 2), "nack_bitmap:", string.format("0x%04X", tvb_uint(tvb(offset, 2), encoding)))
    offset = offset + 2
    subtree:add(tvb(offset, 1), "stream_id:", string.format("0x%02X", tvb(offset, 1):uint()))
    offset = offset + 1

    return offset
end
dds_xrce_types["ACKNACK_Payload"] = ACKNACK_Payload_deserialize

local function HEARTBEAT_Payload_deserialize(tvb, offset, encoding, tree, label)
    local subtree = tree:add(tvb(offset, 5), label)

    offset = unsigned_short_deserialize(tvb, offset, encoding, subtree, "first_unacked_seq_nr:")
    offset = unsigned_short_deserialize(tvb, offset, encoding, subtree, "last_unacked_seq_nr:")
    subtree:add(tvb(offset, 1), "stream_id:", string.format("0x%02X", tvb(offset, 1):uint()))
    offset = offset + 1

    return offset
end
dds_xrce_types["HEARTBEAT_Payload"] = HEARTBEAT_Payload_deserialize

local function TIMESTAMP_Payload_deserialize(tvb, offset, encoding, tree, label)
    local subtree = tree:add(tvb(offset), label)

    return Time_t_deserialize(tvb, offset, encoding, subtree, "transmit_timestamp:")
end
dds_xrce_types["TIMESTAMP_Payload"] = TIMESTAMP_Payload_deserialize

local function TIMESTAMP_REPLY_Payload_deserialize(tvb, offset, encoding, tree, label)
    local subtree = tree:add(tvb(offset), label)

    offset = Time_t_deserialize(tvb, offset, encoding, subtree, "transmit_timestamp:")
    offset = Time_t_deserialize(tvb, offset, encoding, subtree, "receive_timestamp:")
    offset = Time_t_deserialize(tvb, offset, encoding, subtree, "originate_timestamp:")

    return offset
end
dds_xrce_types["TIMESTAMP_REPLY_Payload"] = TIMESTAMP_REPLY_Payload_deserialize
