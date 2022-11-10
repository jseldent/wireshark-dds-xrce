-- DDS-XRCE IDL dissector for Wireshark
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

types = {}
topic_type_names = {}

topic_names = {}
data_reader_topic_names = {}
data_writer_topic_names = {}

function align(x, a)
    return bit.band(x + a - 1, bit.bnot(a - 1))
end

function tvb_int(tvb, encoding)
    encoding = encoding or ENC_BIG_ENDIAN
    local value = 0
    if encoding == ENC_BIG_ENDIAN then
        if tvb:len() <= 4 then
            value = tvb:int()
        else
            value = tvb:int64()
        end
    elseif encoding == ENC_LITTLE_ENDIAN then
        if tvb:len() <= 4 then
            value = tvb:le_int()
        else
            value = tvb:le_int64()
        end
    end
    return value
end

function tvb_uint(tvb, encoding)
    encoding = encoding or ENC_BIG_ENDIAN
    local value = 0
    if encoding == ENC_BIG_ENDIAN then
        if tvb:len() <= 4 then
            value = tvb:uint()
        else
            value = tvb:uint64()
        end
    elseif encoding == ENC_LITTLE_ENDIAN then
        if tvb:len() <= 4 then
            value = tvb:le_uint()
        else
            value = tvb:le_uint64()
        end
    end
    return value
end

function tvb_float(tvb, encoding)
    encoding = encoding or ENC_BIG_ENDIAN
    local value = 0.0
    if encoding == ENC_BIG_ENDIAN then
        value = tvb:float()
    elseif encoding == ENC_LITTLE_ENDIAN then
        value = tvb:le_float()
    end
    return value
end

function char_deserialize(tvb, offset, encoding, tree, label)
    tree:add(tvb(offset, 1), label, string.char(tvb(offset, 1):uint()))
    offset = offset + 1

    return offset
end

function octet_deserialize(tvb, offset, encoding, tree, label)
    tree:add(tvb(offset, 1), label, tvb(offset, 1):uint())
    offset = offset + 1

    return offset
end

function short_deserialize(tvb, offset, encoding, tree, label)
    offset = align(offset, 2)

    tree:add(tvb(offset, 2), label, tvb_int(tvb(offset, 2), encoding))
    offset = offset + 2

    return offset
end

function unsigned_short_deserialize(tvb, offset, encoding, tree, label)
    offset = align(offset, 2)

    tree:add(tvb(offset, 2), label, tvb_uint(tvb(offset, 2), encoding))
    offset = offset + 2

    return offset
end

function long_deserialize(tvb, offset, encoding, tree, label)
    offset = align(offset, 4)

    tree:add(tvb(offset, 4), label, tvb_int(tvb(offset, 4), encoding))
    offset = offset + 4

    return offset
end

function unsigned_long_deserialize(tvb, offset, encoding, tree, label)
    offset = align(offset, 4)

    tree:add(tvb(offset, 4), label, tvb_uint(tvb(offset, 4), encoding))
    offset = offset + 4

    return offset
end

function long_long_deserialize(tvb, offset, encoding, tree, label)
    offset = align(offset, 8)

    tree:add(tvb(offset, 8), label, tvb_int(tvb(offset, 8), encoding))
    offset = offset + 8

    return offset
end

function unsigned_long_long_deserialize(tvb, offset, encoding, tree, label)
    offset = align(offset, 8)

    tree:add(tvb(offset, 8), label, tvb_uint(tvb(offset, 8), encoding))
    offset = offset + 8

    return offset
end

function float_deserialize(tvb, offset, encoding, tree, label)
    offset = align(offset, 4)

    tree:add(tvb(offset, 4), label, tvb_float(tvb(offset, 4), encoding))
    offset = offset + 4

    return offset
end

function double_deserialize(tvb, offset, encoding, tree, label)
    offset = align(offset, 8)

    tree:add(tvb(offset, 8), label, tvb_float(tvb(offset, 8), encoding))
    offset = offset + 8

    return offset
end

function boolean_deserialize(tvb, offset, encoding, tree, label)
    local value = tvb(offset, 1):uint()
    if value > 0 then
        tree:add(tvb(offset, 1), label, "true")
    else
        tree:add(tvb(offset, 1), label, "false")
    end
    offset = offset + 1

    return offset
end

function string_deserialize(tvb, offset, encoding, tree, label)
    offset = align(offset, 4)

    local size = tvb_uint(tvb(offset, 4), encoding)
    offset = offset + 4
    tree:add(tvb(offset, size), label, string.format("\"%s\"", tvb(offset, size):stringz()))
    offset = offset + size

    return offset
end

function sequence_deserialize(tvb, offset, encoding, tree, label, deserialize)
    offset = align(offset, 4)

    local subtree = tree:add(tvb(offset), label)
    local subtree_begin = offset

    local size = tvb_uint(tvb(offset, 4), encoding)
    offset = offset + 4
    if size == 0 then
        subtree:append_text(" [empty]")
    else
        for i = 1, size do
            offset = deserialize(tvb, offset, encoding, subtree, "[" .. tostring(i - 1) .. "]")
        end
    end

    subtree:set_len(offset - subtree_begin)

    return offset
end

function sequence_octet_deserialize(tvb, offset, encoding, tree, label)
    offset = align(offset, 4)

    local size = tvb_uint(tvb(offset, 4), encoding)
    offset = offset + 4
    tree:add(tvb(offset, size), label, tvb(offset, size):bytes():tohex(true, " "))
    offset = offset + size

    return offset
end

function optional_deserialize(tvb, offset, encoding, tree, label, deserialize)
    local has_value = tvb(offset, 1):uint()
    offset = offset + 1
    if has_value > 0 then
        offset = deserialize(tvb, offset, encoding, tree, label)
    end

    return offset
end
