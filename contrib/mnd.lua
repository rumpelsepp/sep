-- Fancy Wireshark Protocol Dissector for MND

mnd_proto = Proto("mnd", "Multicast Node Discovery")

-- Fields
local f_len = ProtoField.uint16("mnd.len", "Length", base.DEC)
local f_payload = ProtoField.bytes("mnd.payload", "Data")
local f_signature = ProtoField.bytes("mnd.signature", "Signature")

mnd_proto.fields = {f_len, f_payload, f_signature}

local cbor_dissector = Dissector.get("cbor")

function mnd_proto.dissector(buffer, pinfo, tree)
   pinfo.cols['protocol'] = 'MND'

   local len = buffer(0, 2)
   local data = buffer(2, len:uint())
   local signature = buffer(len:uint())
   local t_mnd = tree:add(mnd_proto, buffer())

   t_mnd:add(f_len, len)
   t_mnd:add(f_payload, data)
   t_mnd:add(f_signature, signature)

   cbor_dissector:call(data:tvb(), pinfo, tree)
end

udp_table = DissectorTable.get("udp.port")
udp_table:add(7868, mnd_proto)
