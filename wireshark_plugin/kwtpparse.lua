do
	local p_udt = Proto("UDT","UDP-based Data Transfer Protocol","UDT")
	-- 数据包 
	-- local PACKET_TYPE = {[0x00] = "Data Paket", [0x80] = "Control Packet"}
	--local ftmp = ProtoField.new("Paket Type","udt.pkttype",FT_bit,)
	local f_pktdatatype = ProtoField.uint32("udt.pkttype","data",base.HEX,nil, 0x80000000)
	local f_pktctrltype = ProtoField.uint16("udt.pkttype","msg",base.HEX,nil, 0x8000)	
	local f_seqno = ProtoField.uint32("udt.seqno","seq number",base.DEC,nil,0x7FFFFFFF)
	local f_msgno = ProtoField.uint32("udt.msgno","msg number",base.DEC)
	local f_data = ProtoField.bytes("udt.data","data",base.DEC)
	--local f_datalen = ProtoField.bytes("udt.datalength","data",base.DEC)
	
	-- 公共信息	
	local f_ts = ProtoField.uint32("udt.ts","timestamp",base.DEC)
	local f_dstid = ProtoField.uint32("udt.dstid","dst udt socket ID",base.DEC)
	
	-- 控制包 
	local CONTROL_TYPE = {[0x0000] = "handshake",[0x8001] = "keep-alive",[0x8002] = "ack", [0x8003] = "nack", [0x8004] = "congestion", [0x8005] = "shutdown", [0x8006] = "ack of ack", [0x8007] = "packet drop request", [0x8008] = "error:invalid packet type", [0x8009] = "keep-alive reply"}
	local f_type = ProtoField.uint16("udt.msgtype","msg Type",base.HEX,CONTROL_TYPE)
	local f_adinfo = ProtoField.uint32("udt.adinfo","Additional Info Value",base.DEC)
	
	--local f_ownid = ProtoField.uint32("udt.ownid","Source Socket ID",base.DEC)
	--local f_lostlist = ProtoField.uint32("udt.adinfo","Additional Info Value",base.OCT)
	
	p_udt.fields = { f_pktdatatype, f_pktctrltype, f_seqno, f_msgno, f_ts, f_dstid, f_type, f_adinfo, f_data}
	
	
	local data_dis = Dissector.get("data")
	
	function p_udt.dissector(buf,pinfo,tree)	
		local buf_len = buf:len();
		if buf_len < 8 then 
			data_dis.call(buf,pinfo,tree) 
		end

		
		pinfo.cols.protocol:set("udt")
		t = tree:add(p_udt,buf)
		
		pkttype = buf(0,1):uint()
		pkttype = (pkttype / 2^7)
		-- pkttype = (pkttype - (pkttype - 0x80))/2^7
		
		-- 数据包
		-- if (0.0 == pkttype ) then
		if (0 < pkttype and 1 > pkttype ) then				
		    t1 = t:add(buf(0,16), "UDT Data Header")  		
			
            t1:add(f_pktdatatype, buf(0,4))		
			
			seqno = buf(0,4):uint()
			t1:add(f_seqno, buf(0,4))
			
			msgno = buf(4,4):uint()
			t1:add(f_msgno, buf(4,4))
			t1:add(f_ts, buf(8,4))
			dstid = buf(12,4):uint()
			t1:add(f_dstid, buf(12,4))
			t2 = t:add(buf(16,buf_len -16), "UDT Data")
			t2:add(f_data, buf(16,buf_len - 16))	
					
			pinfo.cols.info:set(string.format("dstid="..dstid.." [DATA] seq="..seqno.." msgno="..msgno))			
		-- 控制包
		else		    
			t1 = t:add(buf(0,16), "UDT Message Header")
			t1:add(f_type, buf(0,2))
			type = buf(0,2):uint()
			t1:add(f_adinfo, buf(4,4))
			t1:add(f_ts, buf(8,4))
			dstid = buf(12,4):uint()
			t1:add(f_dstid, buf(12,4))
			t2 = t:add(buf(16,buf_len - 16), "UDT Data")
			local str_msg_sufix
			
			if(type == 0x8000) then
				udtver	   = buf(16,4):uint()
				t2:add(buf(16,4), "udt Version: "..udtver)
				socktype   = buf(20,4):uint()
				t2:add(buf(20,4), "Socket Type: "..socktype)
				initseqno  = buf(24,4):uint()
				t2:add(buf(24,4), "Init Sequence Number: "..initseqno)
				maxpktsize = buf(28,4):uint()
				t2:add(buf(28,4), "Maximum Packet Size: "..maxpktsize)
				maxwinsize = buf(32,4):uint()
				t2:add(buf(32,4), "Maximum Window Size: "..maxwinsize)
				reqtype   = buf(36,4):uint()
				t2:add(buf(36,4), "Connect Type: "..reqtype)
				ownsock    = buf(40,4):uint()
				t2:add(buf(40,4), "Source Socket ID: "..ownsock)
				cookie     = buf(44,4):uint()
				t2:add(buf(44,4), "SYN Cookie: "..cookie)
				ipaddr     = buf(48,16):uint()
				t2:add(buf(48,16), "IP address: "..ipaddr)				
				str_msg_sufix = ", reqtype "..reqtype..", own socket ID "..ownsock
				--pinfo.cols.info:set("handshake: ID "..dstid..", reqtype "..reqtype..", own socket ID "..ownsock)
			elseif (type == 0x8001) then			    
			    str_msg_sufix = ""
                --pinfo.cols.info:set("Keep-alive: ID "..dstid)
			elseif (type == 0x8002) then
			    
			    ackseq = buf(16,4):uint()
                t2:add(buf(16,4), "ACK Sequence: "..ackseq)
                t2:add(buf(20,buf_len - 20), "Other Information:")
                --pinfo.cols.info:set("ACK: ID "..dstid.." ackseq "..ackseq)
				str_msg_sufix = "ack_seq="..ackseq.." ack_num="..buf(4,4):uint()
			elseif (type == 0x8003) then
				local LostCount = ( buf_len - 16 )/4
			    local lostlist = " lostlist "
			    local flag = true
			    
				for i = 1,LostCount do
					lostseq1 = buf(12+4*i,4):uint()
					if(flag) then
						t2:add(buf(12+4*i,4),"Lost Sequence "..i..":", lostseq1)
						if(lostseq1/2^31 > 1) then
							lostseq1 = lostseq1 - 0x80000000
							i = i + 1
							lostseq2 = buf(12+4*i,4):uint()
							t2:add(buf(12+4*i,4),"Lost Sequence "..i..":", lostseq2)
							lostlist = lostlist..lostseq1.." - "..lostseq2.."|"
							flag = false
						else
							lostlist = lostlist..lostseq1.."|"
						end
					end			
				end
			    --pinfo.cols.info:set("NAK: ID "..dstid..lostlist)
				str_msg_sufix = lostlist
			elseif (type == 0x8004) then
			    --pinfo.cols.info:set("Congestion: ID "..dstid)
				str_msg_sufix = ""
			elseif (type == 0x8005) then
			    --pinfo.cols.info:set("Shutdown: ID "..dstid)
				str_msg_sufix = ""
            elseif (type == 0x8006) then
				ack2no = buf(4,4):uint()
			    --pinfo.cols.info:set("ACK of ACK: ID "..dstid.." ACK2 ackno "..ack2no)
				str_msg_sufix = "ack2="..ack2no
            elseif (type == 0x8007) then
                firstseq = buf(16,4):uint()
				lastseq  = buf(20,4):uint()
				t2:add_le(buf(16,4), "First SeqNo: "..firstseq)
				t2:add_le(buf(20,4), "Last SeqNo: "..lastseq)
			    --pinfo.cols.info:set("Msg Drop Req: ID "..dstid)
				str_msg_sufix = ""
            elseif (type == 0x8008) then
			    --pinfo.cols.info:set("Error Signal from the Peer Side: ID "..dstid)
				str_msg_sufix = ""
            elseif (type == 0x8009) then
			    --pinfo.cols.info:set("Keep-alive Reply: ID "..dstid)
				str_msg_sufix = "Replay"
			elseif (type > 0x8009 ) then
			    --pinfo.cols.info:set("unknown packet type "..type.." ID "..dstid)
				str_msg_sufix =""
			end
			
			pinfo.cols.info:set("dstid="..dstid.." ["..string.upper(CONTROL_TYPE[type]).."] "..str_msg_sufix)
		end  -- if end
    end  -- function end
    
    local udp_port_table = DissectorTable.get("udp.port")
	local udt_port = 9908
	udp_port_table:add(udt_port, p_udt)
    
end -- do end
	