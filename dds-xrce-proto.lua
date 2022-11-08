-- DDS-XRCE Protocol dissector for Wireshark
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

require "dds-xrce-types"

local p_dds_xrce = Proto("DDS-XRCE", "DDS for eXtremely Resource Constrained Environments")

local f_tcp_length = ProtoField.uint16("dds-xrce.tcp.length", "length", base.DEC)
local f_canfd_length = ProtoField.uint8("dds-xrce.canfd.length", "length", base.DEC)

local f_session_id = ProtoField.uint8("dds-xrce.session_id", "sessionId", base.HEX)
local f_stream_id = ProtoField.uint8("dds-xrce.stream_id", "streamId", base.HEX)
local f_sequence_nr = ProtoField.uint16("dds-xrce.sequence_nr", "sequenceNr", base.DEC)
local f_client_key = ProtoField.uint32("dds-xrce.client_key", "clientKey", base.HEX)

local f_submessage = ProtoField.none("dds-xrce.submessage", "submessage")
local f_submessage_id = ProtoField.uint8("dds-xrce.submessage.id", "submessageId", base.DEC)
local f_flags = ProtoField.uint8("dds-xrce.submessage.flags", "flags", base.HEX)
local f_flags_endianness =
    ProtoField.uint8(
    "dds-xrce.submessage.flags.endianness",
    "Endianness bit",
    base.HEX,
    {[0] = "Not set", [1] = "Set"},
    0x01
)
local f_flags_reuse =
    ProtoField.uint8("dds-xrce.submessage.flags.reuse", "Reuse bit", base.HEX, {[0] = "Not set", [1] = "Set"}, 0x02)
local f_flags_replace =
    ProtoField.uint8("dds-xrce.submessage.flags.replace", "Replace bit", base.HEX, {[0] = "Not set", [1] = "Set"}, 0x04)
local f_flags_data_format =
    ProtoField.uint8(
    "dds-xrce.submessage.flags.data_format",
    "DataFormat",
    base.HEX,
    {
        [0x0] = "FORMAT_DATA",
        [0x2] = "FORMAT_SAMPLE",
        [0x8] = "FORMAT_DATA_SEQ",
        [0xA] = "FORMAT_SAMPLE_SEQ",
        [0xE] = "FORMAT_PACKED_SAMPLES"
    },
    0x0E
)
local f_flags_last_fragment =
    ProtoField.uint8(
    "dds-xrce.submessage.flags.last_fragment",
    "Last Fragment bit",
    base.HEX,
    {[0] = "Not set", [1] = "Set"},
    0x02
)
local f_submessage_length = ProtoField.uint16("dds-xrce.submessage.length", "submessageLength", base.DEC)

p_dds_xrce.fields = {
    f_tcp_length,
    f_canfd_length,
    f_session_id,
    f_stream_id,
    f_sequence_nr,
    f_client_key,
    f_submessage,
    f_submessage_id,
    f_flags,
    f_flags_endianness,
    f_flags_reuse,
    f_flags_replace,
    f_flags_data_format,
    f_flags_last_fragment,
    f_submessage_length
}

p_dds_xrce.prefs.tcp_ports = Pref.range("TCP port(s)", "2018", "DDS-XRCE TCP port(s)", "65536")
p_dds_xrce.prefs.udp_ports = Pref.range("UDP port(s)", "2018", "DDS-XRCE UDP port(s)", "65536")
p_dds_xrce.prefs.discovery =
    Pref.bool(
    "Dissect XRCE Agent discovery",
    false,
    "Dissect the GET_INFO and INFO messages used for XRCE Agent Discovery. This is disabled by default, since it may conflict with the RTPS dissector."
)
p_dds_xrce.prefs.tcp_discovery_ports =
    Pref.range("TCP discovery port(s)", "", "TCP/IP XRCE Agent discovery port", "65536")
p_dds_xrce.prefs.udp_discovery_ports =
    Pref.range("UDP discovery port(s)", "7400", "UDP/IP XRCE Agent discovery port(s)", "65536")
p_dds_xrce.prefs.track_objects =
    Pref.bool(
    "Track DDS entities",
    true,
    "Track the creation and use of DDS entities to enable the dissection of topic and type names."
)
p_dds_xrce.prefs.deserialize_types =
    Pref.bool(
    "Deserialize user-defined data types",
    true,
    "Enable the deserialization of user-defined data types via custom deserialization functions."
)

local info
local session_id
local stream_id
local sequence_nr
local fragments = {}
local submessages = {}

local function dds_xrce_submessage(tvb, pinfo, tree, offset)
    local subtree = tree:add(f_submessage, tvb(offset))

    local submessage_id = tvb(offset, 1):uint()
    subtree:add(f_submessage_id, tvb(offset, 1))
    offset = offset + 1

    local flags = tvb(offset, 1):uint()
    local t_flags = subtree:add(f_flags, tvb(offset, 1))
    if submessage_id == 1 then
        -- CREATE
        if bit.band(flags, 0x04) == 0x04 then
            t_flags:append_text(", Replace bit")
        end
        t_flags:add(f_flags_replace, tvb(offset, 1))
        if bit.band(flags, 0x02) == 0x02 then
            t_flags:append_text(", Reuse bit")
        end
        t_flags:add(f_flags_reuse, tvb(offset, 1))
    elseif submessage_id == 7 or submessage_id == 9 then
        -- WRITE_DATA or DATA
        if bit.band(flags, 0x0E) == 0x00 then
            t_flags:append_text(", FORMAT_DATA")
        elseif bit.band(flags, 0x0E) == 0x02 then
            t_flags:append_text(", FORMAT_SAMPLE")
        elseif bit.band(flags, 0x0E) == 0x08 then
            t_flags:append_text(", FORMAT_DATA_SEQ")
        elseif bit.band(flags, 0x0E) == 0x0A then
            t_flags:append_text(", FORMAT_SAMPLE_SEQ")
        elseif bit.band(flags, 0x0E) == 0x0E then
            t_flags:append_text(", FORMAT_PACKED_SAMPLES")
        end
        t_flags:add(f_flags_data_format, tvb(offset, 1))
    elseif submessage_id == 13 then
        -- FRAGMENT
        if bit.band(flags, 0x02) == 0x02 then
            t_flags:append_text(", Last Fragment bit")
        end
        t_flags:add(f_flags_last_fragment, tvb(offset, 1))
    end
    local encoding = ENC_BIG_ENDIAN
    if bit.band(flags, 0x01) == 0x01 then
        t_flags:append_text(", Endianness bit")
        encoding = ENC_LITTLE_ENDIAN
    end
    t_flags:add(f_flags_endianness, tvb(offset, 1))
    offset = offset + 1

    local submessage_length = tvb(offset, 2):le_uint()
    subtree:add_le(f_submessage_length, tvb(offset, 2))
    offset = offset + 2

    subtree:set_len(4 + submessage_length)

    local type_name = nil
    if submessage_id == 0 then
        info = info .. ", CREATE_CLIENT"
        subtree:set_text("CREATE_CLIENT")
        type_name = "CREATE_CLIENT_Payload"
    elseif submessage_id == 1 then
        info = info .. ", CREATE"
        subtree:set_text("CREATE")
        type_name = "CREATE_Payload"
    elseif submessage_id == 2 then
        info = info .. ", GET_INFO"
        subtree:set_text("GET_INFO")
        type_name = "GET_INFO_Payload"
    elseif submessage_id == 3 then
        info = info .. ", DELETE"
        subtree:set_text("DELETE")
        type_name = "DELETE_Payload"
    elseif submessage_id == 4 then
        info = info .. ", STATUS_AGENT"
        subtree:set_text("STATUS_AGENT")
        type_name = "STATUS_AGENT_Payload"
    elseif submessage_id == 5 then
        info = info .. ", STATUS"
        subtree:set_text("STATUS")
        type_name = "STATUS_Payload"
    elseif submessage_id == 6 then
        info = info .. ", INFO"
        subtree:set_text("INFO")
        type_name = "INFO_Payload"
    elseif submessage_id == 7 then
        info = info .. ", WRITE_DATA"
        subtree:set_text("WRITE_DATA")
        if bit.band(flags, 0x0E) == 0x00 then
            -- FORMAT_DATA
            info = info .. " (FORMAT_DATA)"
            type_name = "WRITE_DATA_Payload_Data"
        elseif bit.band(flags, 0x0E) == 0x02 then
            -- FORMAT_SAMPLE
            info = info .. " (FORMAT_SAMPLE)"
            type_name = "WRITE_DATA_Payload_Sample"
        elseif bit.band(flags, 0x0E) == 0x08 then
            -- FORMAT_DATA_SEQ
            info = info .. " (FORMAT_DATA_SEQ)"
            type_name = "WRITE_DATA_Payload_DataSeq"
        elseif bit.band(flags, 0x0E) == 0x0A then
            -- FORMAT_SAMPLE_SEQ
            info = info .. " (FORMAT_SAMPLE_SEQ)"
            type_name = "WRITE_DATA_Payload_SampleSeq"
        elseif bit.band(flags, 0x0E) == 0x0E then
            -- FORMAT_PACKED_SAMPLES
            info = info .. " (FORMAT_PACKED_SAMPLES)"
            type_name = "WRITE_DATA_Payload_PackedSamples"
        end
    elseif submessage_id == 8 then
        info = info .. ", READ_DATA"
        subtree:set_text("READ_DATA")
        type_name = "READ_DATA_Payload"
    elseif submessage_id == 9 then
        info = info .. ", DATA"
        subtree:set_text("DATA")
        if bit.band(flags, 0x0E) == 0x00 then
            -- FORMAT_DATA
            info = info .. " (FORMAT_DATA)"
            type_name = "DATA_Payload_Data"
        elseif bit.band(flags, 0x0E) == 0x02 then
            -- FORMAT_SAMPLE
            info = info .. " (FORMAT_SAMPLE)"
            type_name = "DATA_Payload_Sample"
        elseif bit.band(flags, 0x0E) == 0x08 then
            -- FORMAT_DATA_SEQ
            info = info .. " (FORMAT_DATA_SEQ)"
            type_name = "DATA_Payload_DataSeq"
        elseif bit.band(flags, 0x0E) == 0x0A then
            -- FORMAT_SAMPLE_SEQ
            info = info .. " (FORMAT_SAMPLE_SEQ)"
            type_name = "DATA_Payload_SampleSeq"
        elseif bit.band(flags, 0x0E) == 0x0E then
            -- FORMAT_PACKED_SAMPLES
            info = info .. " (FORMAT_PACKED_SAMPLES)"
            type_name = "DATA_Payload_PackedSamples"
        end
    elseif submessage_id == 10 then
        info = info .. ", ACKNACK"
        subtree:set_text("ACKNACK")
        type_name = "ACKNACK_Payload"
        info = info .. string.format(" (0x%02X, %u)", tvb(offset + 4, 1):uint(), tvb_uint(tvb(offset, 2), encoding) - 1)
    elseif submessage_id == 11 then
        info = info .. ", HEARTBEAT"
        subtree:set_text("HEARTBEAT")
        type_name = "HEARTBEAT_Payload"
        info = info .. string.format(" (0x%02X, %u)", tvb(offset + 4, 1):uint(), tvb_uint(tvb(offset, 2), encoding) - 1)
    elseif submessage_id == 12 then
        info = info .. ", RESET"
        subtree:set_text("RESET")
    elseif submessage_id == 13 then
        info = info .. ", FRAGMENT"
        subtree:set_text("FRAGMENT")
        if bit.band(flags, 0x02) == 0x02 then
            info = info .. " (last)"
        end
        -- Store the fragment.
        if not pinfo.visited then
            -- Store the fragment.
            if fragments[stream_id] == nil then
                fragments[stream_id] = {}
            end
            fragments[stream_id][sequence_nr] = tvb(offset, submessage_length):bytes()
        end
    elseif submessage_id == 14 then
        info = info .. ", TIMESTAMP"
        subtree:set_text("TIMESTAMP")
        type_name = "TIMESTAMP_Payload"
    elseif submessage_id == 15 then
        info = info .. ", TIMESTAMP_REPLY"
        subtree:set_text("TIMESTAMP_REPLY")
        type_name = "TIMESTAMP_REPLY_Payload"
    end

    if type_name ~= nil and dds_xrce_types[type_name] ~= nil then
        dds_xrce_types[type_name](
            tvb(offset, submessage_length):tvb(),
            0,
            encoding,
            subtree,
            "payload (" .. type_name .. ")"
        )
    elseif submessage_length > 0 then
        subtree:add(tvb(offset, submessage_length), "payload:", tvb(offset, submessage_length):bytes():tohex(true, " "))
    end

    offset = offset + align(submessage_length, 4)

    -- If this is the last fragment, create a new submessage by reassembling the fragments.
    if submessage_id == 13 and bit.band(flags, 0x02) == 0x02 then
        -- Cache the reassembled submessage during the first visit.
        if not pinfo.visited then
            if fragments[stream_id] ~= nil then
                local bytes = ByteArray.new()
                -- Order the fragments by sequence number.
                local sequence_nrs = {}
                for i in pairs(fragments[stream_id]) do
                    table.insert(sequence_nrs, i)
                end
                table.sort(sequence_nrs)
                for _, i in ipairs(sequence_nrs) do
                    bytes = bytes .. fragments[stream_id][i]
                end
                fragments[stream_id] = nil
                if bytes:len() >= 4 then
                    submessages[pinfo.number] = bytes
                end
            end
        end
        -- Add the reassembled submessage to the packet containing the last FRAGMENT.
        if submessages[pinfo.number] ~= nil then
            dds_xrce_submessage(
                ByteArray.tvb(submessages[pinfo.number], "Reassembled DDS-XRCE submessage"),
                pinfo,
                tree,
                0
            )
        end
    end

    return offset
end

local function dds_xrce_get_len(tvb, pinfo, offset)
    return tvb(offset, 2):le_uint() + 2
end

local function dds_xrce_dissect(tvb, pinfo, tree)
    pinfo.cols.protocol = "DDS-XRCE"
    info = ""

    local subtree = tree:add(p_dds_xrce, tvb(), "DDS-XRCE Protocol")
    local offset = 0

    if pinfo.port_type == 2 then
        -- TCP
        subtree:add_le(f_tcp_length, tvb(offset, 2))
        offset = offset + 2
    elseif pinfo.port_type == 0 then
        -- CANFD
        subtree:add(f_canfd_length, tvb(offset, 1))
        offset = offset + 1
    end

    session_id = tvb(offset, 1):uint()
    local t_session_id = subtree:add(f_session_id, tvb(offset, 1))
    if session_id == 0x00 then
        t_session_id:append_text(" (SESSION_ID_NONE_WITH_CLIENT_KEY)")
    elseif session_id == 0x80 then
        t_session_id:append_text(" (SESSION_ID_NONE_WITHOUT_CLIENT_KEY)")
    end
    offset = offset + 1
    info = info .. string.format("0x%02X", session_id)
    subtree:append_text(string.format(", sessionId: 0x%02X", session_id))

    stream_id = tvb(offset, 1):uint()
    local t_stream_id = subtree:add(f_stream_id, tvb(offset, 1))
    if stream_id == 0x00 then
        t_stream_id:append_text(" (STREAMID_NONE)")
    elseif stream_id == 0x01 then
        t_stream_id:append_text(" (STREAMID_BUILTIN_BEST_EFFORTS)")
    elseif stream_id == 0x80 then
        t_stream_id:append_text(" (STREAMID_BUILTIN_RELIABLE)")
    end
    if stream_id >= 0x80 then
        t_stream_id:add(tvb(offset, 1), "reliability:", "RELIABLE")
    elseif stream_id >= 0x01 then
        t_stream_id:add(tvb(offset, 1), "reliability:", "BEST_EFFORTS")
    end
    offset = offset + 1
    info = info .. string.format(":0x%02X", stream_id)
    subtree:append_text(string.format(", streamId: 0x%02X", stream_id))

    sequence_nr = tvb(offset, 2):le_uint()
    subtree:add_le(f_sequence_nr, tvb(offset, 2))
    offset = offset + 2
    info = info .. string.format(" (%u)", sequence_nr)

    if session_id < 0x80 then
        subtree:add_le(f_client_key, tvb(offset, 4))
        offset = offset + 4
    end

    while offset < tvb:len() do
        offset = dds_xrce_submessage(tvb, pinfo, subtree, offset)
    end

    pinfo.cols.info = info

    return offset
end

function p_dds_xrce.init()
    DissectorTable.get("tcp.port"):add(p_dds_xrce.prefs.tcp_ports, p_dds_xrce)
    DissectorTable.get("udp.port"):add(p_dds_xrce.prefs.udp_ports, p_dds_xrce)
    if p_dds_xrce.prefs.discovery then
        DissectorTable.get("tcp.port"):add(p_dds_xrce.prefs.tcp_discovery_ports, p_dds_xrce)
        DissectorTable.get("udp.port"):add(p_dds_xrce.prefs.udp_discovery_ports, p_dds_xrce)
    end

    dds_xrce_types_init(p_dds_xrce.prefs.track_objects == true, p_dds_xrce.prefs.deserialize_types == true)

    fragments = {}
    submessages = {}
end

function p_dds_xrce.dissector(tvb, pinfo, tree)
    if pinfo.port_type == 2 then
        -- TCP
        dissect_tcp_pdus(tvb, tree, 2, dds_xrce_get_len, dds_xrce_dissect)
    elseif pinfo.port_type == 3 then
        -- UDP
        dds_xrce_dissect(tvb, pinfo, tree)
    elseif pinfo.port_type == 0 then
        -- CANFD
        dds_xrce_dissect(tvb, pinfo, tree)
    end
end

DissectorTable.get("tcp.port"):add_for_decode_as(p_dds_xrce)
DissectorTable.get("udp.port"):add_for_decode_as(p_dds_xrce)
DissectorTable.get("can.subdissector"):add_for_decode_as(p_dds_xrce)

if gui_enabled() then
    dds_xrce_types_menu(MENU_TOOLS_UNSORTED)
end
