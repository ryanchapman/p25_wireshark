-- p25cai.lua
-- Wireshark dissector for APCO Project 25 Common Air Interface
--
-- Ryan A. Chapman <ryan@rchapman.org>
-- Friday, April 25, 2025
--
--
-- This lua implementation is based on packet-p25cai.c in the op25 project
-- https://gitea.osmocom.org/op25/op25-legacy.git
-- op25-legacy/wireshark/plugins/p25/packet-p25cai.c
--
-- Routines for APCO Project 25 Common Air Interface dissection
-- Copyright 2008, Michael Ossmann <mike@ossmann.com>
--
-- Wireshark - Network traffic analyzer
-- By Gerald Combs <gerald@wireshark.org>
-- Copyright 1998 Gerald Combs
--
-- This program is free software; you can redistribute it and/or
-- modify it under the terms of the GNU General Public License
-- as published by the Free Software Foundation; either version 2
-- of the License, or (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with this program; if not, write to the Free Software
-- Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
--
-- The general structure, debug, and prefs of this lua script are based
-- on dns_dissector.lua, which can be found in the Wireshark repo under
-- test/lua/dns_dissector.lua
--
-- -- script-name: dns_dissector.lua
--
-- -- author: Hadriel Kaplan <hadrielk at yahoo dot com>
-- -- Copyright (c) 2014, Hadriel Kaplan
-- -- This code is in the Public Domain, or the BSD (3 clause) license if
-- -- Public Domain does not apply in your country.
--


local inspect = require("inspect")

-- do not modify this table
local debug_level = {
  DISABLED = 0,
  LEVEL_1  = 1,
  LEVEL_2  = 2
}

-- set this DEBUG to debug_level.LEVEL_1 to enable printing debug_level info
-- set it to debug_level.LEVEL_2 to enable really verbose printing
-- note: this will be overridden by user's preference settings
local DEBUG = debug_level.LEVEL_2

local default_settings =
  {
    debug_level  = DEBUG,
    port = 23456,
    enabled = true,
  }

-- for testing purposes, we want to be able to pass in changes to the defaults
-- from the command line; because you can't set lua preferences from the command
-- line using the '-o' switch (the preferences don't exist until this script is
-- loaded, so the command line thinks they're invalid preferences being set)
-- so we pass them in as command arguments insetad, and handle it here
--
-- example: tshark -V -r /tmp/p25_tsdu.pcapng -X lua_script:`pwd`/p25cai.lua -X lua_script1:debug_level=LEVEL_2 -X lua_script1:port=1234
if not gui_enabled() then
  local args={...} -- get passed-in args
  if args and #args > 0 then
    for _, arg in ipairs(args) do
      local name, value = arg:match("(.+)=(.+)")
      if name and value then
        if tonumber(value) then
          value = tonumber(value)
        elseif value == "true" or value == "TRUE" then
          value = true
        elseif value == "false" or value == "FALSE" then
          value = false
        elseif value == "DISABLED" then
          value = debug_level.DISABLED
        elseif value == "LEVEL_1" then
          value = debug_level.LEVEL_1
        elseif value == "LEVEL_2" then
          value = debug_level.LEVEL_2
        else
          error("invalid commandline argument value")
        end
      else
        error("invalid commandline argument syntax, want K=V, got " .. arg)
      end

      default_settings[name] = value
    end
  end
end

local dprint = function() end
local dprint2 = function() end
local function reset_debug_level()
  if default_settings.debug_level > debug_level.DISABLED then
    dprint = function(...)
      io.write(table.concat({"Lua[p25cai]:", ...}," "))
      io.write("\n")
    end

    if default_settings.debug_level > debug_level.LEVEL_1 then
      dprint2 = dprint
    end
  end
end
-- call it now
reset_debug_level()

dprint2("Wireshark version = ", get_version())
dprint2("Lua version = ", _VERSION)

local major, minor, micro = get_version():match("(%d+)%.(%d+)%.(%d+)")
if major and tonumber(major) <= 4 and ((tonumber(minor) <= 4) or (tonumber(minor) == 5 and tonumber(micro) < 0)) then
  error(  "Sorry, but your Wireshark/Tshark version ("..get_version()..") is too old for this script!\n"..
          "This script needs Wireshark/Tshark version 4.5.0 or higher.\n" )
end

-- more sanity checking
-- verify we have the ProtoExpert class in wireshark, as that's the newest thing this file uses
assert(ProtoExpert.new, "Wireshark does not have the ProtoExpert class, so it's too old - get the latest 1.11.3 or higher")


-- Constants
local FRAME_SYNC_MAGIC = 0x5575F5FF77FF

data_unit_ids = {
  [0x0] = "Header Data Unit",
  [0x3] = "Terminator without Link Control",
  [0x5] = "Logical Link Data Unit 1",
  [0x7] = "Trunking Signaling Data Unit",
  [0xA] = "Logical Link Data Unit 2",
  [0xC] = "Packet Data Unit",
  [0xF] = "Terminator with Link Control"
}

network_access_codes = {
  [0x293] = "Default NAC",
  [0xF7E] = "Receiver to open on any NAC",
  [0xF7F] = "Repeater to receive and retransmit any NAC"
}

manufacturer_ids = {
  -- From https://connect.tiaonline.org/viewdocument/mfid-assignments-2016-01-27
  [0x00] = "Standard MFID (pre-2001)",
  [0x01] = "Standard MFID (post-2001)",
  [0x09] = "Aselsan Inc.",
  [0x10] = "BK Radio (fka Relm)",
  [0x18] = "Airbus (fka EADS Public Safety Inc.)",
  [0x20] = "Cycomm",
  [0x28] = "Efratom Time and Frequency Products, Inc",
  [0x30] = "Com-Net Ericsson",
  [0x34] = "Etherstack",
  [0x38] = "Datron",
  [0x40] = "Icom",
  [0x48] = "Garmin",
  [0x50] = "GTE",
  [0x55] = "IFR Systems",
  [0x5A] = "INIT Innovations in Transportation, Inc",
  [0x60] = "GEC-Marconi",
  [0x64] = "Harris Corporation (inactive)",
  [0x68] = "Kenwood Communications",
  [0x70] = "Glenayre Electronics",
  [0x74] = "Japan Radio Co.",
  [0x78] = "Kokusai",
  [0x7C] = "Maxon",
  [0x80] = "Midland",
  [0x86] = "Daniels Electronics Ltd.",
  [0x90] = "Motorola",
  [0xA0] = "Thales",
  [0xA4] = "Harris Corporation (fka Tyco, M/A-COM, Com-Net Ericsson, Ericsson)",
  [0xAA] = "National Regional Planning Council (NRPC)",
  [0xB0] = "Raytheon",
  [0xC0] = "SEA",
  [0xC8] = "Securicor",
  [0xD0] = "ADI",
  [0xD8] = "Tait Electronics",
  [0xE0] = "Teletec",
  [0xF0] = "EF Johnson (fka Transcrypt International)",
  [0xF8] = "Vertex Standard",
  [0xFC] = "Zetron, Inc"
}

link_control_formats = {
  [0x00] = "Group Call Format",
  [0x03] = "Individual Call Format",
  [0x80] = "Encrypted Group Call Format",
  [0x83] = "Encrypted Individual Call Format"
}

link_control_opcodes = {
  -- From AABF
  [0x00] = "Group Voice Channel User (LCGVR)",
  [0x01] = "Reserved",
  [0x02] = "Group Voice Channel Update (LCGVU)",
  [0x03] = "Unit to Unit Voice Channel User (LCUVR)",
  [0x04] = "Group Voice Channel Update - Explicit (LCGVUX)",
  [0x05] = "Unit to Unit Answer Request (LCUAQ)",
  [0x06] = "Telephone Interconnect Voice Channel User (LCTVR)",
  [0x07] = "Telephone Interconnect Answer Request (LCTAQ)",
  [0x08] = "Reserved",
  [0x09] = "Reserved",
  [0x0A] = "Reserved",
  [0x0B] = "Reserved",
  [0x0C] = "Reserved",
  [0x0D] = "Reserved",
  [0x0E] = "Reserved",
  [0x0F] = "Call Termination/Cancellation (LCCT)",
  [0x10] = "Group Affiliation Query (LCGAQ)",
  [0x11] = "Unit Registration Command (LCRC)",
  [0x12] = "Unit Authentication Command (LCAC)",
  [0x13] = "Status Query (LCSQ)",
  [0x14] = "Status Update (LCSU)",
  [0x15] = "Message Update (LCMU)",
  [0x16] = "Call Alert (LCCA)",
  [0x17] = "Extended Function Command (LCEFC)",
  [0x18] = "Channel Identifier Update (LCCIU)",
  [0x19] = "Channel Identifier Update - Explicit (LCCIUX)",
  [0x1A] = "Reserved",
  [0x1B] = "Reserved",
  [0x1C] = "Reserved",
  [0x1D] = "Reserved",
  [0x1E] = "Reserved",
  [0x1F] = "Reserved",
  [0x20] = "System Service Broadcast (LCSSB)",
  [0x21] = "Secondary Control Channel Broadcast (LCSCB)",
  [0x22] = "Adjacent Site Status Broadcast (LCASB)",
  [0x23] = "RFSS Status Broadcast (LCRSB)",
  [0x24] = "Network Status Broadcast (LCNSB)",
  [0x25] = "Protection Parameter Broadcast (LCPPB)",
  [0x26] = "Secondary Control Channel Broadcast - Explicit (LCSCBX)",
  [0x27] = "Adjacent Site Status Broadcast - Explicit (LCASBX)",
  [0x28] = "RFSS Status Broadcast - Explicit (LCRSBX)",
  [0x29] = "Network Status Broadcast - Explicit (LCNSBX)",
  [0x2A] = "Reserved",
  [0x2B] = "Reserved",
  [0x2C] = "Reserved",
  [0x2D] = "Reserved",
  [0x2E] = "Reserved",
  [0x2F] = "Reserved",
  [0x30] = "Reserved",
  [0x31] = "Reserved",
  [0x32] = "Reserved",
  [0x33] = "Reserved",
  [0x34] = "Reserved",
  [0x35] = "Reserved",
  [0x36] = "Reserved",
  [0x37] = "Reserved",
  [0x38] = "Reserved",
  [0x39] = "Reserved",
  [0x3A] = "Reserved",
  [0x3B] = "Reserved",
  [0x3C] = "Reserved",
  [0x3D] = "Reserved",
  [0x3E] = "Reserved",
  [0x3F] = "Reserved",
}

talk_group_ids = {
  {0x0000, 0x0000, "No One (used for individual calls)"},
  {0x0001, 0x0001, "Default Talk Group (used in systems with no other talk groups defined)"},
  {0x0002, 0xFFFE, "Regular Talk Group"},
  {0xFFFF, 0xFFFF, "Everyone"},
}

key_ids = {
  [0x0000] = "Default Key ID"
}

algorithm_ids = {
  -- From http://ftp.tiaonline.org/TR-8/TR815/Public/ALGID_Guide_040528.doc
  -- Type I
  [0x00] = "ACCORDION 1.3",
  [0x01] = "BATON (Auto Even)",
  [0x02] = "FIREFLY Type 1",
  [0x03] = "MAYFLY Type 1",
  [0x04] = "SAVILLE",
  [0x05] = "Motorola Assigned - PADSTONE",
  [0x41] = "BATON (Auto Odd)",
  -- Type III
  [0x80] = "Unencrypted message",
  [0x81] = "DES-OFB, 56 bit key",
  [0x82] = "2 key Triple DES",
  [0x83] = "3 key Triple DES, 168 bit key",
  [0x84] = "AES-256-OFB",
  [0x85] = "AES-128-ECB",
  [0x88] = "AES-CBC",
  [0x89] = "AES-128-OFB",
  -- Motorola proprietary
  [0x9F] = "Motorola DES-XL 56-bit key",
  [0xA0] = "Motorola DVI-XL",
  [0xA1] = "Motorola DVP-XL",
  [0xA2] = "Motorola DVI-XL-SPFL",
  [0xA3] = "Motorola HAYSTACK",
  [0xA4] = "Motorola Assigned - Unknown",
  [0xA5] = "Motorola Assigned - Unknown",
  [0xA6] = "Motorola Assigned - Unknown",
  [0xA7] = "Motorola Assigned - Unknown",
  [0xA8] = "Motorola Assigned - Unknown",
  [0xA9] = "Motorola Assigned - Unknown",
  [0xAA] = "Motorola ADP (40 bit RC4)",
  [0xAB] = "Motorola CFX-256",
  [0xAC] = "Motorola GOST 28147-89 (RFC 5830)",
  [0xAD] = "Motorola Assigned - LOCALIZED",
  [0xAE] = "Motorola Assigned - Unknown",
  [0xAF] = "Motorola AES+",
  [0xB0] = "Motorola DVP",
  [0xD0] = "Motorola LOCAL_BR"
}

service_access_points = {
  [0x00] = "Unencrypted User Data",
  [0x01] = "Encrypted User Data",
  [0x02] = "Circuit Data",
  [0x03] = "Circuit Data Control",
  [0x04] = "Packet Data",
  [0x05] = "Address Resolution Protocol",
  [0x06] = "SNDCP Packet Data Control",
  [0x1F] = "Extended Address",
  [0x20] = "Registration and Authorization",
  [0x21] = "Channel Reassignment",
  [0x22] = "System Configuration",
  [0x23] = "MR Loop-Back",
  [0x24] = "MR Statistics",
  [0x25] = "MR Out-of-Service",
  [0x26] = "MR Paging",
  [0x27] = "MR Configuration",
  [0x28] = "Unencrypted Key Management Message",
  [0x29] = "Encrypted Key Management Message",
  [0x3D] = "Trunking Control",
  [0x3F] = "Protected Trunking Control"
}

isp_opcodes = {
  -- Voice service isp
  [0x00] = "Group Voice Service Request",
  [0x04] = "Unit To Unit Voice Service Request",
  [0x05] = "Unit To Unit Answer Response",
  [0x08] = "Telephone Interconnect Request - Explicit Dialing",
  [0x09] = "Telephone Interconnect Request - Implicit Dialing",
  [0x0A] = "Telephone Interconnect Answer Response",
  -- Data service isp
  [0x10] = "Individual Data Service Request (obsolete)",
  [0x11] = "Group Data Service Request (obsolete)",
  [0x12] = "SNDCP Data Channel Request",
  [0x13] = "SNDCP Data Page Response",
  [0x14] = "SNDCP Reconnect Request",
  -- Control and status isp
  [0x20] = "Acknowledge Response - Unit",
  [0x2E] = "Authentication Query",
  [0x2F] = "Authentication Response",
  [0x1F] = "Call Alert Request",
  [0x23] = "Cancel Service Request",
  [0x27] = "Emergency Alarm Request",
  [0x24] = "Extended Function Response",
  [0x29] = "Group Affiliation Query Response",
  [0x28] = "Group Affiliation Request",
  [0x32] = "Identifier Update Request",
  [0x1C] = "Message Update Request",
  [0x30] = "Protection Parameter Request",
  [0x1A] = "Status Query Request",
  [0x19] = "Status Query Response",
  [0x18] = "Status Update Request",
  [0x2C] = "Unit Registration Request",
  [0x2B] = "De-Registration Request",
  [0x2D] = "Location Registration Request",
  [0x1D] = "Radio Unit Monitor Request",
  [0x36] = "Roaming Address Request",
  [0x37] = "Roaming Address Response"
}

osp_opcodes = {
  -- Voice service osp
  [0x00] = "Group Voice Channel Grant",
  [0x02] = "Group Voice Channel Grant Update",
  [0x03] = "Group Voice Channel Grant Update - Explicit",
  [0x04] = "Unit To Unit Voice Channel Grant",
  [0x05] = "Unit To Unit Answer Request",
  [0x06] = "Unit To Unit Voice Channel Grant Update",
  [0x08] = "Telephone Interconnect Voice Channel Grant",
  [0x09] = "Telephone Interconnect Voice Channel Grant Update",
  [0x0A] = "Telephone Interconnect Answer Request",
  -- Data service osp
  [0x10] = "Individual Data Channel Grant (obsolete)",
  [0x11] = "Group Data Channel Grant (obsolete)",
  [0x12] = "Group Data Channel Announcement (obsolete)",
  [0x13] = "Group Data Channel Announcement Explicit (obsolete)",
  [0x14] = "SNDCP Data Channel Grant",
  [0x15] = "SNDCP Data Page Request",
  [0x16] = "SNDCP Data Channel Announcement - Explicit",
  -- Control and status osp
  [0x20] = "Acknowledge Response - FNE",
  [0x3C] = "Adjacent Status Broadcast",
  [0x2E] = "Authentication Command",
  [0x1F] = "Call Alert",
  [0x27] = "Deny Response",
  [0x24] = "Extended Function Command",
  [0x2A] = "Group Affiliation Query",
  [0x28] = "Group Affiliation Response",
  [0x3D] = "Identifier Update",
  [0x1C] = "Message Update",
  [0x3B] = "Network Status Broadcast",
  [0x3E] = "Protection Parameter Broadcast",
  [0x3F] = "Protection Parameter Update",
  [0x21] = "Queued Response",
  [0x3A] = "RFSS Status Broadcast",
  [0x39] = "Secondary Control Channel Broadcast",
  [0x1A] = "Status Query",
  [0x18] = "Status Update",
  [0x38] = "System Service Broadcast",
  [0x2D] = "Unit Registration Command",
  [0x2C] = "Unit Registration Response",
  [0x2F] = "De-Registration Acknowledge",
  [0x2B] = "Location Registration Response",
  [0x1D] = "Radio Unit Monitor Command",
  [0x36] = "Roaming Address Command",
  [0x37] = "Roaming Address Update",
  [0x35] = "Time and Date Announcement",
  [0x34] = "Identifier Update for VHF/UHF Bands",
  [0x29] = "Secondary Control Channel Broadcast - Explicit"
}

pdu_formats = {
  [0x03] = "Response Packet",
  [0x15] = "Unconfirmed Data Packet",
  [0x16] = "Confirmed Data Packet",
  [0x17] = "Alternate Multiple Block Trunking Control Packet"
}


-- Status symbol can be one of 4 values:
-- HEX  BIN  USED_BY                 DESCRIPTION
-- 0x0 (00b) SUBSCRIBER              unknown, used by talk-around
-- 0x1 (01b) REPEATER                busy
-- 0x2 (10b) REPEATER OR SUBSCRIBER  unknown, used for inbound and outbound
-- 0x3 (11b) REPEATER                idle
--
-- Note that there are two values used for `unknown`.
-- 0x0 00b is used by a subscriber when sending a message on a direct channel
-- 0x2 10b when a subscriber sends a message inbound to a repeater, it sets status symbol to 10b.
--
status_symbols = {
  [0x0] = "Unknown (set by subscriber: used by talk-around)",
  [0x1] = "Busy (set by repeater)",
  [0x2] = "Unknown (set by subscriber: used for inbound or outbound)",
  [0x3] = "Idle (set by repeater: start of inbound slot)"
}

-- Declare the protocol (after value tables)
local p25cai = Proto("p25cai", "APCO Project 25 Common Air Interface")

-- Define the protocol fields
local f = p25cai.fields

f.fs             = ProtoField.bytes("p25cai.fs", "Frame Synchronization", base.NONE)
f.nid            = ProtoField.uint64("p25cai.nid", "Network ID Codeword", base.HEX)
f.nac            = ProtoField.uint16("p25cai.nac", "Network Access Code", base.HEX, network_access_codes, 0xFFF0)
f.duid           = ProtoField.uint16("p25cai.duid", "Data Unit ID", base.HEX, data_unit_ids, 0x000F)
f.hdu            = ProtoField.none("p25cai.hdu", "Header Data Unit", base.NONE)
f.tsbk           = ProtoField.none("p25cai.tsbk", "Trunking Signaling Block", base.NONE)
f.pdu            = ProtoField.none("p25cai.pdu", "Packet Data Unit", base.NONE)
f.ldu1           = ProtoField.none("p25cai.ldu1", "Logical Link Data Unit 1", base.NONE)
f.ldu2           = ProtoField.none("p25cai.ldu2", "Logical Link Data Unit 2", base.NONE)
f.mi             = ProtoField.bytes("p25cai.mi", "Message Indicator (initialization vector [IV])", base.NONE) -- 72 bits, 9 bytes
f.mfid           = ProtoField.uint8("p25cai.mfid", "Manufacturer's ID", base.HEX, manufacturer_ids)
f.algid          = ProtoField.uint8("p25cai.algid", "Algorithm ID", base.HEX, algorithm_ids)
f.kid            = ProtoField.uint16("p25cai.kid", "Key ID", base.HEX, key_ids)
f.tgid           = ProtoField.uint16("p25cai.tgid", "Talk Group ID", base.RANGE_STRING, talk_group_ids)
f.ss_parent      = ProtoField.none("p25cai.ss_parent", "Status Symbols", base.NONE)
f.ss             = ProtoField.uint8("p25cai.ss", "Status Symbol", base.HEX, status_symbols, 0x3)
f.lc             = ProtoField.none("p25cai.lc", "Link Control", base.NONE)
f.lcf            = ProtoField.uint8("p25cai.lcf", "Link Control Format", base.HEX, link_control_formats)
f.lbf            = ProtoField.bool("p25cai.lbf", "Last Block Flag", 8, nil, 0x80) -- 0x80 is binary 10000000 (MSB)
f.ei             = ProtoField.bool("p25cai.ei", "Emergency Indicator", 8, nil, 0x80)
f.ptbf           = ProtoField.bool("p25cai.ptbf", "Protected Trunking Block Flag", 8, nil, 0x40) -- 0x40 is binary 01000000 (2nd MSB)
f.isp_opcode     = ProtoField.uint8("p25cai.isp.opcode", "Opcode", base.HEX, isp_opcodes, 0x3F)
f.osp_opcode     = ProtoField.uint8("p25cai.osp.opcode", "Opcode", base.HEX, osp_opcodes, 0x3F)
f.unknown_opcode = ProtoField.uint8("p25cai.unknown.opcode", "Unknown Opcode (non-standard MFID)", base.HEX, nil, 0x3F)
f.args           = ProtoField.uint64("p25cai.args", "Arguments", base.HEX)
f.tuid           = ProtoField.uint24("p25cai.tuid", "Target Unit ID")
f.srcuid         = ProtoField.uint24("p25cai.suid", "Source Unit ID")
f.dstuid         = ProtoField.uint24("p25cai.suid", "Destination Unit ID")
f.crc            = ProtoField.uint16("p25cai.crc", "CRC", base.HEX)
f.imbe           = ProtoField.bytes("p25cai.imbe", "Raw IMBE Frame", base.NONE)
-- Low Speed Data (LSD) [16 bits, 2 bytes] is used for custom user applications not defined by p25cai (e.g. GPS coordinates).
-- total capacity of 88.89 bps.  Encoded with shortened cyclic code to create 64 bits [8 bytes] per superframe.
f.lsd            = ProtoField.uint16("p25cai.lsd", "Low Speed Data", base.HEX)
f.es             = ProtoField.none("p25cai.es", "Encryption Sync", base.NONE)
f.an             = ProtoField.bool("p25cai.an", "A/N", 8, nil, 0x40)
f.io             = ProtoField.bool("p25cai.io", "I/O", 8, nil, 0x20)
f.pdu_format     = ProtoField.uint8("p25cai.pdu.format", "Format", base.HEX, pdu_formats, 0x1F)
f.sapid          = ProtoField.uint8("p25cai.sapid", "SAP ID", base.HEX, service_access_points, 0x3F)
f.llid           = ProtoField.uint24("p25cai.llid", "Logical Link ID", base.DEC)
f.fmf            = ProtoField.bool("p25cai.fmf", "Full Message Flag", 8, nil, 0x80)
f.btf            = ProtoField.uint8("p25cai.btf", "Blocks to Follow", base.DEC, nil, 0x7F)
f.poc            = ProtoField.uint8("p25cai.poc", "Pad Octet Count", base.HEX, nil, 0x1F)
f.syn            = ProtoField.bool("p25cai.syn", "Syn", 8, nil, 0x80)
f.ns             = ProtoField.uint8("p25cai.ns", "N(S)", base.HEX, nil, 0x70)
f.fsnf           = ProtoField.uint8("p25cai.fsnf", "Fragment Sequence Number Field", base.HEX, nil, 0x0F)
f.dho            = ProtoField.uint8("p25cai.dho", "Data Header Offset", base.HEX, nil, 0x3F)
f.db             = ProtoField.none("p25cai.db", "Data Block", base.NONE)
f.dbsn           = ProtoField.uint8("p25cai.dbsn", "Data Block Serial Number", base.HEX, nil, 0xFE)
f.crc9           = ProtoField.uint16("p25cai.crc9", "CRC", base.HEX, nil, 0x1FF)
f.ud             = ProtoField.bytes("p25cai.ud", "User Data", base.NONE)
f.packet_crc     = ProtoField.uint32("p25cai.packet_crc", "Packet CRC", base.HEX)
f.class          = ProtoField.uint8("p25cai.class", "Response Class", base.HEX, nil, 0xA0)
f.type           = ProtoField.uint8("p25cai.type", "Response Type", base.HEX, nil, 0x38)
f.status         = ProtoField.uint8("p25cai.status", "Response Status", base.HEX, nil, 0x07)
f.x              = ProtoField.bool("p25cai.x", "X", 8, nil, 0x80)
f.sllid          = ProtoField.uint24("p25cai.sllid", "Source Logical Link ID", base.HEX)

-- TODO: implement unit id
-- Unit ID [24 bit, 3 byte] is user programmable, and is used for individual and group calling.  This is used for
-- both source ID and destination ID.  User ID is not the same as the Electronic Serial Number (ESN) of the radio.
-- Ranges:
-- 0x000000              no one (never assigned to a radio unit)
-- 0x000001 to 0x98967F  general use
-- 0x989680 to 0xFFFFFE  talk groups or special purposes
-- 0xFFFFFF              everyone (used for a group call with a TGID)

--------------------------------------------------------------------------------
-- preferences handling stuff
--------------------------------------------------------------------------------
-- In the GUI, these preferences can be changed by accessing:
--  Wireshark GUI > Preferences > Protocols > P25CAI
--   or
--  Wireshark GUI > Preferences > Advanced > (search for p25)
--
-- a "enum" table for our enum pref, as required by Pref.enum()
-- having the "index" number makes ZERO sense, and is completely illogical
-- but it's what the code has expected it to be for a long time. Ugh.
local debug_pref_enum = {
  { 1,  "Disabled", debug_level.DISABLED },
  { 2,  "Level 1",  debug_level.LEVEL_1  },
  { 3,  "Level 2",  debug_level.LEVEL_2  },
}

p25cai.prefs.debug = Pref.enum("Debug", default_settings.debug_level,
                               "The debug printing level", debug_pref_enum)

p25cai.prefs.port  = Pref.uint("Port number", default_settings.port,
                               "The UDP port number for P25 incoming traffic")

p25cai.prefs.enabled  = Pref.bool("filter enabled", default_settings.enabled,
                                  "Whether P25 dissection is enabled or not")

----------------------------------------
-- a function for handling prefs being changed
function p25cai.prefs_changed()
  dprint("P25CAI prefs_changed called")

  default_settings.debug_level  = p25cai.prefs.debug
  reset_debug_level()

  default_settings.enabled = p25cai.prefs.enabled

  if default_settings.port ~= p25cai.prefs.port then
    -- remove old one, if not 0
    if default_settings.port ~= 0 then
      dprint2("removing P25CAI from port", default_settings.port)
      DissectorTable.get("udp.port"):remove(default_settings.port, p25cai)
    end
    -- set our new default
    default_settings.port = p25cai.prefs.port
    -- add new one, if not 0
    if default_settings.port ~= 0 then
      dprint2("adding P25CAI to port", default_settings.port)
      DissectorTable.get("udp.port"):add(default_settings.port, p25cai)
    end
  end

end

dprint2("P25CAI Prefs registered")


-- Utility functions
local function count_bits(n)
  local count = 0
  while n > 0 do
    count = count + 1
    n = bit.band(n, n - 1)
  end
  return count
end

local function find_min(list, len)
  local min = list[1]
  local index = 1
  local unique = true

  for i = 2, len do
    if list[i] < min then
      min = list[i]
      index = i
      unique = true
    elseif list[i] == min then
      unique = false
    end
  end

  if not unique then
    return -1
  end

  return index
end

-- Fake error correction decoders (as in the original C code)
-- These just extract bits without actual error correction
local function golay_18_6_8_decode(codeword)
  return bit.rshift(bit.band(codeword, 0x3FFFF), 12)
end

local function golay_24_12_8_decode(codeword)
  return bit.rshift(bit.band(codeword, 0xFFFFFF), 12)
end

local function hamming_10_6_3_decode(codeword)
  return bit.rshift(bit.band(codeword, 0x3FF), 4)
end

local function cyclic_16_8_5_decode(codeword, decoded)
  decoded[1] = bit.rshift(codeword, 24)
  decoded[2] = bit.rshift(codeword, 8)
end

local function rs_24_12_13_decode(codeword, decoded)
  for i = 1, 9 do
    decoded[i] = codeword[i]
  end
end

local function rs_24_16_9_decode(codeword, decoded)
  for i = 1, 12 do
    decoded[i] = codeword[i]
  end
end

local function rs_36_20_17_decode(codeword, decoded)
  for i = 1, 15 do
    decoded[i] = codeword[i]
  end
end

-- Dissector implementations for various frame types

local function dissect_voice(tvb, tree, offset)
  -- Add IMBE frames
  tree:add(f.imbe, tvb(offset, 18))
  offset = offset + 18
  tree:add(f.imbe, tvb(offset, 18))
  offset = offset + 23
  tree:add(f.imbe, tvb(offset, 18))
  offset = offset + 23
  tree:add(f.imbe, tvb(offset, 18))
  offset = offset + 23
  tree:add(f.imbe, tvb(offset, 18))
  offset = offset + 23
  tree:add(f.imbe, tvb(offset, 18))
  offset = offset + 23
  tree:add(f.imbe, tvb(offset, 18))
  offset = offset + 23
  tree:add(f.imbe, tvb(offset, 18))
  offset = offset + 22
  tree:add(f.imbe, tvb(offset, 18))
end

local function dissect_lc(tvb, tree)
  local lc_tree = tree:add(f.lc, tvb(0, 9))
  local lcf = tvb(0, 1):uint()
  lc_tree:add(f.lcf, tvb(0, 1))

  if lcf == 0x00 then -- 0x00 = Group Call Format
    lc_tree:add(f.mfid, tvb(1, 1))
    lc_tree:add(f.ei, tvb(2,1))
    lc_tree:add(f.tgid, tvb(4,2))
    lc_tree:add(f.srcuid, tvb(6,3))
  elseif lcf == 0x03 then -- 0x03 = Individual Call Format
    -- TODO: need to test this with a radio which isn't on a trunked system
    lc_tree:add(f.mfid, tvb(1, 1))
    lc_tree:add(f.dstuid, tvb(3, 3))
    lc_tree:add(f.srcuid, tvb(6, 3))
  -- TODO: implement encryption (if key is known)
  -- else if lcf == 0x80 -- Encrypted Group Call Format
  -- else if lcf == 0x83 -- Encrypted Individual Call Format
  end
end

local function dissect_es(tvb, tree)
  local es_tree = tree:add(f.es, tvb(0, 12))
  es_tree:add(f.mi, tvb(0, 9))
  es_tree:add(f.algid, tvb(9, 1))
  es_tree:add(f.kid, tvb(10, 2))
end

local function extract_status_symbols(tvb, pinfo, tree)
  local raw_length = tvb:len()
  local extracted_length = raw_length - math.floor(raw_length / 36)
  local outbound = 0

  -- Create buffer to become new tvb
  local extracted_buffer = ByteArray.new()
  extracted_buffer:set_size(extracted_length)

  -- Create status symbol subtree
  local ss_parent_item = tree:add(f.ss_parent, tvb(0))
  local ss_tree = ss_parent_item

  -- Go through frame one dibit at a time
  local i, j = 0, 0
  while i < raw_length * 4 do
    if i % 36 == 35 then
      -- After every 35 dibits is a status symbol
      ss_tree:add(f.ss, tvb(math.floor(i/4), 1))
      -- Check to see if the status symbol is odd
      if bit.band(tvb(math.floor(i/4), 1):uint(), 0x1) ~= 0 then
        -- Flag as outbound (only outbound frames should have odd status symbols)
        outbound = bit.bor(outbound, 1)
      end
    else
      -- Extract frame bits from between status symbols
      local byte_pos = math.floor((i * 2) / 8)
      local bit_offset = (i * 2) % 8
      local dibit = bit.band(bit.rshift(tvb(byte_pos, 1):uint(), 6 - bit_offset), 0x3)

      local out_byte = math.floor(j / 4)
      local out_shift = 6 - (j % 4) * 2
      local current = extracted_buffer:get_index(out_byte)
      extracted_buffer:set_index(out_byte, bit.bor(current, bit.lshift(dibit, out_shift)))
      j = j + 1
    end
    i = i + 1
  end

  -- Setup a new tvb buffer with the extracted data
  local extracted_tvb = ByteArray.tvb(extracted_buffer, "P25 Common Air Interface")
  return extracted_tvb, outbound
end

-- Build Header Data Unit tvb
local function build_hdu_tvb(tvb, pinfo, offset)
  -- Check we have enough data
  if tvb:len() - offset < 81 then
    return tvb(0,0)  -- Return empty tvb if not enough data
  end

  -- Initialize buffers
  local rs_codeword = {}
  local hdu_buffer = {}

  for i = 0, 26 do rs_codeword[i] = 0 end
  for i = 0, 14 do hdu_buffer[i] = 0 end

  -- Each 18 bits is a Golay codeword
  local i = offset * 8
  for j = 0, 210, 6 do
    -- Take 18 bits from the tvb, adjusting for byte boundaries
    local byte_pos = math.floor(i / 8)
    local bit_offset = i % 8

    -- Need to extract 18 bits across byte boundaries
    local golay_codeword = 0

    -- Get first byte
    local first_byte = tvb(byte_pos, 1):uint()
    -- Calculate bits available in first byte
    local bits_from_first = 8 - bit_offset

    if bits_from_first >= 18 then
      -- All 18 bits fit in the first byte (rare case)
      golay_codeword = bit.band(bit.rshift(first_byte, 8 - bit_offset - 18), 0x3FFFF)
    else
      -- We need multiple bytes
      -- Add bits from first byte
      golay_codeword = bit.lshift(bit.band(first_byte, bit.rshift(0xFF, bit_offset)), 18 - bits_from_first)

      -- Add bits from second byte
      local bits_needed = 18 - bits_from_first
      local second_byte = tvb(byte_pos + 1, 1):uint()

      if bits_needed <= 8 then
        -- Second byte has all remaining bits
        golay_codeword = bit.bor(golay_codeword,
                                 bit.rshift(second_byte, 8 - bits_needed))
      else
        -- Need bits from second and third bytes
        golay_codeword = bit.bor(golay_codeword, bit.lshift(second_byte, bits_needed - 8))

        -- Add bits from third byte
        local third_byte = tvb(byte_pos + 2, 1):uint()
        golay_codeword = bit.bor(golay_codeword,
                                 bit.rshift(third_byte, 16 - bits_needed))
      end
    end

    -- Apply Golay decoding (produces 6 bits)
    local rs_code_byte = bit.lshift(golay_18_6_8_decode(golay_codeword), 2)

    -- Stuff high bits into one byte of the new buffer
    local byte_idx = math.floor(j / 8)
    local bit_idx = j % 8
    local high_byte = bit.rshift(rs_code_byte, bit_idx)
    rs_codeword[byte_idx] = bit.bor(rs_codeword[byte_idx], high_byte)

    -- Stuff low bits into the next unless beyond end of buffer
    if j < 210 then
      local low_byte = bit.lshift(rs_code_byte, 8 - bit_idx)
      rs_codeword[byte_idx + 1] = bit.bor(rs_codeword[byte_idx + 1], low_byte)
    end

    -- Move to next 18-bit chunk
    i = i + 18
  end

  -- Apply Reed-Solomon decoding to get the actual HDU data
  rs_36_20_17_decode(rs_codeword, hdu_buffer)

  -- Create a new TVB buffer with the decoded data
	local ba = ByteArray.new()
	ba:set_size(15)  -- Allocate space for 15 bytes

	for i = 0, 14 do
		-- Make sure the value is a valid byte (0-255)
		local value = hdu_buffer[i] or 0
		if type(value) ~= "number" then
			value = 0
		else
			value = bit.band(value, 0xFF)  -- Ensure it's in range 0-255
		end

		ba:set_index(i, value)
	end


  local hdu_tvb = ba:tvb("Header Data Unit")

  return hdu_tvb
end

-- Deinterleave data block. Assumes output buffer is already zeroed.
local function data_deinterleave(tvb, bit_offset)
  local deinterleaved = {}
  for i = 0, 24 do deinterleaved[i] = 0 end

  local d, i, j, t
  local steps = {0, 52, 100, 148}

  -- Step through input nibbles to copy to output
  i = bit_offset
  d = 0
  while i < 45 + bit_offset do
    for j = 0, 3 do
      -- t = tvb bit index
      -- d = deinterleaved bit index
      t = i + steps[j + 1]

      -- Get byte and bit positions
      local byte_pos = math.floor(t / 8)
      local bit_pos = t % 8
      local d_byte = math.floor(d / 8)
      local d_bit = d % 8

      -- Extract nibble and place it in output
      local tvb_byte = tvb(byte_pos, 1):uint()
      local nibble = bit.band(bit.lshift(tvb_byte, bit_pos), 0xF0)
      deinterleaved[d_byte] = bit.bor(deinterleaved[d_byte], bit.rshift(nibble, d_bit))

      d = d + 4
    end
    i = i + 4
  end

  -- Handle last nibble separately
  t = bit_offset + 48
  local byte_pos = math.floor(t / 8)
  local bit_pos = t % 8
  local tvb_byte = tvb(byte_pos, 1):uint()
  local nibble = bit.band(bit.lshift(tvb_byte, bit_pos), 0xF0)
  deinterleaved[24] = bit.bor(deinterleaved[24], nibble)

  return deinterleaved
end

-- 1/2 rate trellis decoder
local function trellis_1_2_decode(encoded, offset)
  -- Initialize the output buffer
  local decoded = {}
  for i = 0, 11 do decoded[i + offset] = 0 end

  -- Initialize state to 0 (not a0)
  local state = 0  -- This was likely the issue - ensure it's initialized to a number

  -- State transition table, including constellation to dibit pair mapping
  local next_words = {
    {0x2, 0xC, 0x1, 0xF},  -- state 0
    {0xE, 0x0, 0xD, 0x3},  -- state 1
    {0x9, 0x7, 0xA, 0x4},  -- state 2
    {0x5, 0xB, 0x6, 0x8}   -- state 3
  }

  -- Process the data
  for i = 0, 192, 4 do  -- Process each 4-bit codeword
    -- Check bounds
    if math.floor(i/8) + 1 > #encoded then
      print(string.format("Lua: Warning: i/8 = %.1f exceeds encoded length %d", i/8, #encoded))
      break
    end

    -- Extract codeword (4 bits from the input)
    local byte_idx = math.floor(i / 8)
    local bit_offset = i % 8

    -- Ensure byte_idx is within bounds
    if byte_idx >= #encoded then
      print("Lua: Error: byte_idx out of bounds:", byte_idx, "#encoded =", #encoded)
      break
    end

    local codeword = 0
    if bit_offset <= 4 then
      -- Codeword is entirely within one byte
      codeword = bit.band(bit.rshift(encoded[byte_idx], 4 - bit_offset), 0xF)
    else
      -- Codeword spans two bytes
      -- Make sure we don't run past the end of the buffer
      if byte_idx + 1 >= #encoded then
        print("Lua: Error: byte_idx + 1 out of bounds:", byte_idx + 1, "#encoded =", #encoded)
        break
      end

      local bits_from_first = 8 - bit_offset
      local bits_from_second = 4 - bits_from_first

      local first_part = bit.band(encoded[byte_idx], bit.lshift(1, bits_from_first) - 1)
      local second_part = bit.rshift(encoded[byte_idx + 1], 8 - bits_from_second)

      codeword = bit.bor(bit.lshift(first_part, bits_from_second), second_part)
    end

    -- Calculate Hamming distance to each possible codeword from current state
    local hd = {0, 0, 0, 0}  -- Initialize with default values
    for k = 0, 3 do
      hd[k + 1] = count_bits(bit.bxor(codeword, next_words[state + 1][k + 1]))
    end

    -- Find the minimum Hamming distance
    local min_hd = hd[1]
    local dibit_idx = 0
    for k = 1, 4 do
      if hd[k] < min_hd then
        min_hd = hd[k]
        dibit_idx = k - 1
      end
    end

    -- Determine next state based on current state and selected dibit
    local prev_state = state
    state = dibit_idx

    -- Write dibit to output
    local out_byte = math.floor(i / 16) + offset
    local out_shift = 6 - 2 * (math.floor(i / 4) % 4)

    if out_byte < offset + 12 then -- Ensure we're within the output buffer
      decoded[out_byte] = bit.bor(decoded[out_byte] or 0, bit.lshift(dibit_idx, out_shift))
    end
  end

  return decoded
end

-- Build Trunking Signaling Block tvb
local function build_tsdu_tvb(tvb, pinfo, offset)
  -- From here on, our tvb offset may not fall on bit boundaries, so we track
  -- it by bits instead of bytes
  local tvb_bit_offset = offset * 8
  local tsdu_offset = 0
  local block_offset = 0
  local last_block = 0

  local tsdu_buffer = {}
  -- 12 bytes for each TSDU, max of 3 TSDUs
  for i = 0, 35 do
    tsdu_buffer[i] = 0
  end

  -- Process blocks until last block flag is set
  while (offset + block_offset + 23) < tvb:len() do
    -- Ensure we have enough data remaining
    if tvb:len() - math.floor(tvb_bit_offset / 8) < 25 then
      error("ASSERT FAILURE: not enough data left to process another TSDU block")
    end

    -- Deinterleave data
    local trellis_buffer = data_deinterleave(tvb, tvb_bit_offset)

    -- Apply trellis decoding
    local decoded_block = trellis_1_2_decode(trellis_buffer, tsdu_offset)

    for i = tsdu_offset, tsdu_offset + 11 do
      tsdu_buffer[i] = decoded_block[i]
    end

    -- Check if this is the last block
    last_block = bit.rshift(tsdu_buffer[tsdu_offset], 7)

    -- Move to next block
    tvb_bit_offset = tvb_bit_offset + 196
    block_offset = block_offset + 24
    tsdu_offset = tsdu_offset + 12
  end

  local ba = ByteArray.new()
  ba:set_size(tsdu_offset) -- Allocate space for tsdu_offset bytes

  for i = 0, tsdu_offset - 1 do
    -- Make sure the value is a valid byte (0-255)
    local value = tsdu_buffer[i] or 0
    if type(value) ~= "number" then
      value = 0
    else
      value = bit.band(value, 0xFF) -- Ensure it's in range 0-255
    end
    ba:set_index(i, value)
  end

  local tsdu_tvb = ba:tvb("Trunking Signaling Block")
  return tsdu_tvb
end


-- TODO: test this once we have a sample packet
-- Build Link Control tvb from LDU1
local function build_ldu_lc_tvb(tvb, pinfo, offset)
    -- Start from the correct offset within the LDU
    offset = offset + 36

    -- Make sure we have enough data
    if tvb:reported_length_remaining(offset) < 147 then
        return tvb:range(0, 0):tvb() -- Return an empty TVB instead of nil
    end

    -- Allocate buffers for the Reed-Solomon codeword and LC buffer
    local rs_codeword = {}
    for i = 1, 18 do rs_codeword[i] = 0 end

    local lc_buffer = {}
    for i = 1, 9 do lc_buffer[i] = 0 end

    -- Step through TVB bits to find 10-bit Hamming codewords
    local r = 0 -- Reed-Solomon codeword bit index
    for i = offset * 8, (offset * 8) + 143 * 184, 184 do
        for j = 0, 30, 10 do
            -- t = TVB bit index
            local t = i + j

            -- Calculate the byte position and bit offset
            local byte_pos = math.floor(t / 8)
            local bit_offset = t % 8

            -- Get 4 bytes as a 32-bit network-order integer
            local uint32 = 0
            if byte_pos + 3 < tvb:len() then
                uint32 = tvb:bytes(byte_pos, 4):uint()
            else
                -- If we don't have 4 bytes, use what we have
                local available = tvb:reported_length() - byte_pos
                if available > 0 then
                    uint32 = tvb:bytes(byte_pos, available):uint()
                    uint32 = bit.lshift(uint32, (4 - available) * 8)
                end
            end

            -- Extract the 10-bit codeword by shifting and masking
            local shift_amount = 22 - bit_offset
            local hamming_codeword = bit.band(bit.rshift(uint32, shift_amount), 0x3FF)

            -- Decode the Hamming codeword to get 6 bits of data
            local rs_code_byte = bit.lshift(hamming_10_6_3_decode(hamming_codeword), 2)

            -- Calculate bit position in rs_codeword
            local high_byte_idx = math.floor(r / 8) + 1
            if high_byte_idx <= 18 then  -- Make sure we don't go beyond the rs_codeword array
                local high_byte = bit.rshift(rs_code_byte, (r % 8))
                rs_codeword[high_byte_idx] = bit.bor(rs_codeword[high_byte_idx], high_byte)

                -- Stuff low bits into next byte unless beyond buffer end
                if r < 144 then
                    local low_byte_idx = high_byte_idx + 1
                    if low_byte_idx <= 18 then  -- Make sure we don't go beyond the rs_codeword array
                        local low_byte = bit.lshift(rs_code_byte, (8 - r % 8))
                        rs_codeword[low_byte_idx] = bit.bor(rs_codeword[low_byte_idx], low_byte)
                    end
                end
            end

            -- Increment bit index for next iteration
            r = r + 6

            -- Break if we've processed all 144 bits
            if r >= 144 then
                break
            end
        end

        -- Break if we've processed all 144 bits
        if r >= 144 then
            break
        end
    end

    -- Apply Reed-Solomon decoding
    rs_24_12_13_decode(rs_codeword, lc_buffer)

    -- Create a new TVB from the lc_buffer
    -- Create ByteArray directly with preset values to avoid string operations
    local lc_bytearray = ByteArray.new()
    -- Pre-allocate with 9 zeros
    lc_bytearray:set_size(9)
    -- Set the values
    for i = 1, 9 do
        lc_bytearray:set_index(i-1, bit.band(lc_buffer[i], 0xFF))
    end

    -- Create the new TVB
    local lc_tvb = ByteArray.tvb(lc_bytearray, "Link Control")

    return lc_tvb
end

-- Helper function for cyclic code decoding 16,8,5
-- This is a "fake" decoder that just extracts first byte of each 16-bit word, as in the C++ version
local function cyclic_16_8_5_decode(codeword, out_buffer)
  -- Take the first byte of each 16-bit word
  out_buffer[1] = bit.band(bit.rshift(codeword, 24), 0xFF) -- High byte of high word
  out_buffer[2] = bit.band(bit.rshift(codeword, 8), 0xFF)  -- High byte of low word
end

-- TODO: need a sample low speed packet to test this.  Can I do that with a Harris radio?
--       maybe op25 can xmit this type of packet.
-- Low speed data tvb
local function build_ldu_lsd_tvb(tvb, pinfo, offset)
    -- Start from the correct offset within the LDU
    offset = offset + 174

    -- Make sure we have enough data
    if tvb:len() - offset < 4 then
        return tvb:range(0, 0):tvb() -- Return an empty TVB instead of nil
    end

    -- Allocate buffer for the LSD
    local lsd_buffer = {0, 0}  -- 2-byte buffer initialized with zeros

    -- Get 4 bytes as a 32-bit integer in network byte order
    local uint32 = tvb:range(offset, 4):uint()

    -- Apply cyclic decoding
    cyclic_16_8_5_decode(uint32, lsd_buffer)

    -- Create a new TVB from the lsd_buffer
    -- Create ByteArray directly with preset values to avoid string operations
    local lsd_bytearray = ByteArray.new()
    -- Pre-allocate with 2 zeros
    lsd_bytearray:set_size(2)
    -- Set the values
    lsd_bytearray:set_index(0, bit.band(lsd_buffer[1], 0xFF))
    lsd_bytearray:set_index(1, bit.band(lsd_buffer[2], 0xFF))

    -- Create the new TVB
    local lsd_tvb = ByteArray.tvb(lsd_bytearray, "Low Speed Data")

    -- Add as a data source - this may not be needed and could cause issues
    -- pinfo.data_src:add_proto_data(lsd_tvb, "Low Speed Data")

    return lsd_tvb
end

-- fake (24,16,9) Reed-Solomon decoder, no error correction
-- TODO: make less fake
local function rs_24_16_9_decode(rs_codeword, out_buffer)
  -- Just grab the first 12 bytes (16 sets of six bits)
  for i = 1, 12 do
    out_buffer[i] = rs_codeword[i]
  end
end

local function hamming_10_6_3_decode(codeword)
  -- Return the 6 bits starting from bit 4 (right-shift by 4)
  return bit.band(bit.rshift(codeword, 4), 0x3F)
end

-- Build Link Control tvb from Terminator
function build_term_lc_tvb(tvb, pinfo, offset)
    -- Make sure we have enough data
    if tvb:len() - offset < 36 then
        return tvb:range(0, 0):tvb() -- Return an empty TVB instead of nil
    end

    -- Allocate buffers for the Reed-Solomon codeword and LC buffer
    local rs_codeword = {}
    for i = 1, 18 do rs_codeword[i] = 0 end

    local lc_buffer = {}
    for i = 1, 9 do lc_buffer[i] = 0 end

    -- Process Golay codewords
    local j = 0 -- Reed-Solomon bit index
    for i = offset * 8, (offset * 8) + 143, 24 do
        -- Calculate the byte position and bit offset
        local byte_pos = math.floor(i / 8)
        local bit_offset = i % 8

        -- Get 4 bytes as a 32-bit network-order integer
        local uint32 = 0
        if byte_pos + 3 < tvb:len() then
            uint32 = tvb:range(byte_pos, 4):uint()
        else
            -- If we don't have 4 bytes, use what we have
            local available = tvb:len() - byte_pos
            if available > 0 then
                uint32 = tvb:range(byte_pos, available):uint()
                uint32 = bit.lshift(uint32, (4 - available) * 8)
            end
        end

        -- Extract the 24-bit Golay codeword by shifting and masking
        local shift_amount = 8 - bit_offset
        local golay_codeword = bit.band(bit.rshift(uint32, shift_amount), 0xFFFFFF)

        -- Decode the Golay codeword to get 12 bits of data and shift left by 4
        local rs_code_chunk = bit.lshift(golay_24_12_8_decode(golay_codeword), 4)

        -- Calculate bit position in rs_codeword
        local high_byte_idx = math.floor(j / 8) + 1
        if high_byte_idx <= 18 then  -- Make sure we don't go beyond the rs_codeword array
            -- Stuff high bits into current byte
            local high_byte = bit.rshift(rs_code_chunk, (j % 8))
            rs_codeword[high_byte_idx] = bit.bor(rs_codeword[high_byte_idx], high_byte)

            -- Stuff low bits into next byte
            local low_byte_idx = high_byte_idx + 1
            if low_byte_idx <= 18 then  -- Make sure we don't go beyond the rs_codeword array
                local low_byte = bit.lshift(rs_code_chunk, (8 - j % 8))
                rs_codeword[low_byte_idx] = bit.bor(rs_codeword[low_byte_idx], low_byte)
            end
        end

        -- Increment bit index for next iteration (12 bits per Golay decode)
        j = j + 12

        -- Break if we've processed all 144 bits
        if j >= 144 then
            break
        end
    end

    -- Apply Reed-Solomon decoding
    rs_24_12_13_decode(rs_codeword, lc_buffer)

    -- Create a new TVB from the lc_buffer
    -- Create ByteArray directly with preset values to avoid string operations
    local lc_bytearray = ByteArray.new()
    -- Pre-allocate with 9 zeros
    lc_bytearray:set_size(9)
    -- Set the values
    for i = 1, 9 do
        lc_bytearray:set_index(i-1, bit.band(lc_buffer[i], 0xFF))
    end

    -- Create the new TVB
    local lc_tvb = ByteArray.tvb(lc_bytearray, "Link Control")

    return lc_tvb
end


-- Build encryption sync tvb
local function build_ldu_es_tvb(tvb, pinfo, offset)
  -- Start from the correct offset within the LDU
  offset = offset + 36

  -- Make sure we have enough data
  if tvb:len() - offset < 147 then
    return tvb:range(0, 0):tvb() -- Return an empty TVB instead of nil
  end

  -- Allocate buffers for the Reed-Solomon codeword and ES buffer
  local rs_codeword = {}
  for i = 1, 18 do rs_codeword[i] = 0 end

  local es_buffer = {}
  for i = 1, 12 do es_buffer[i] = 0 end

  -- Step through TVB bits to find 10-bit Hamming codewords
  local r = 0 -- Reed-Solomon codeword bit index
  for i = offset * 8, (offset * 8) + 143 * 184, 184 do
    for j = 0, 30, 10 do
      -- t = TVB bit index
      local t = i + j

      -- Calculate the byte position and bit offset
      local byte_pos = math.floor(t / 8)
      local bit_offset = t % 8

      -- Get 4 bytes as a 32-bit network-order integer
      local uint32 = 0
      if byte_pos + 3 < tvb:len() then
        -- Use get_uint to get a 32-bit unsigned integer directly
        uint32 = tvb:range(byte_pos, 4):uint()
      else
        -- If we don't have 4 bytes, use what we have
        local available = tvb:len() - byte_pos
        if available > 0 then
          uint32 = tvb:range(byte_pos, available):uint()
          uint32 = bit.lshift(uint32, (4 - available) * 8)
        end
      end

      -- Extract the 10-bit codeword by shifting and masking
      local shift_amount = 22 - bit_offset
      local hamming_codeword = bit.band(bit.rshift(uint32, shift_amount), 0x3FF)

      -- Decode the Hamming codeword to get 6 bits of data
      local rs_code_byte = bit.lshift(hamming_10_6_3_decode(hamming_codeword), 2)

      -- Calculate bit position in rs_codeword
      local high_byte_idx = math.floor(r / 8) + 1
      if high_byte_idx <= 18 then  -- Make sure we don't go beyond the rs_codeword array
        local high_byte = bit.rshift(rs_code_byte, (r % 8))
        rs_codeword[high_byte_idx] = bit.bor(rs_codeword[high_byte_idx], high_byte)

        -- Stuff low bits into next byte unless beyond buffer end
        if r < 144 then
          local low_byte_idx = high_byte_idx + 1
          if low_byte_idx <= 18 then  -- Make sure we don't go beyond the rs_codeword array
            local low_byte = bit.lshift(rs_code_byte, (8 - r % 8))
            rs_codeword[low_byte_idx] = bit.bor(rs_codeword[low_byte_idx], low_byte)
          end
        end
      end

      -- Increment bit index for next iteration
      r = r + 6

      -- Break if we've processed all 144 bits
      if r >= 144 then
        break
      end
    end

    -- Break if we've processed all 144 bits
    if r >= 144 then
      break
    end
  end

  -- Apply Reed-Solomon decoding
  rs_24_16_9_decode(rs_codeword, es_buffer)

  -- Create a new TVB from the es_buffer
  -- In Wireshark Lua, ByteArray constructor can take a hex string
  local hex_string = ""
  for i = 1, 12 do
    -- Ensure values are within byte range and convert to hex
    hex_string = hex_string .. string.format("%02x ", bit.band(es_buffer[i], 0xFF))
  end

  -- Create ByteArray from the hex string (remove trailing space)
  local es_bytearray = ByteArray.new(hex_string:sub(1, -2))

  -- Create the new TVB using ByteArray.tvb()
  local es_tvb = ByteArray.tvb(es_bytearray, "Encryption Sync")

  -- Optionally add as a data source to the pinfo - this may not be needed
  -- and might even be causing issues
  -- pinfo.cols.protocol = "P25"
  -- pinfo.cols.info:append(" Encryption Sync")

  return es_tvb
end


local function byte_to_binary(n)
  local binary = ""
  for i = 7, 0, -1 do
    binary = binary .. ((bit.band(n, bit.lshift(1, i)) == 0) and "0" or "1")
  end
  return binary
end

-- Function to convert a byte to its binary representation
function byte_to_binary(byte)
    local binary = ""
    for i = 7, 0, -1 do
        binary = binary .. ((byte & (1 << i)) > 0 and "1" or "0")
    end
    return binary
end

-- Function to print TVB bytes with offset, hex, and binary representation
-- Example usage:
-- print_tvb_bytes(tsdu_tvb, tsdu_offset, 32, "last_block " .. last_block)
function print_tvb_bytes(tvb, offset, length, label)
    local label = label or ""  -- Default empty label if not provided

    dprint(string.format("%s tvb:length = %d", label, tvb:len()))

    -- Ensure we don't try to read beyond the TVB
    local max_length = math.min(length, tvb:len() - offset)

    -- Determine format for byte numbering based on length
    local byte_format = "byte%d"
    if max_length >= 10 and max_length < 100 then
        byte_format = "byte%02d"
    elseif max_length >= 100 and max_length < 1000 then
        byte_format = "byte%03d"
    elseif max_length >= 1000 and max_length < 10000 then
        byte_format = "byte%04d"
    end

    for i = 0, max_length - 1 do
        local byte = tvb(offset + i, 1):uint()
        local byte_label = string.format(byte_format, i+1)

        dprint(string.format("%s %s[%d]: 0x%02X (binary %s)",
                            label,
                            byte_label,
                            offset + i,
                            byte,
                            byte_to_binary(byte)))
    end
end

local function dissect(tvb, pinfo, tree)
  if not default_settings.enabled then
    return 0
  end

  -- Check minimum length
  --
  -- If this doesn't look like a P25 CAI frame, give up and return 0 so that
  -- perhaps another dissector can take over.
  if tvb:len() < 14 then
    return 0
  end

  -- Set protocol name
  pinfo.cols.protocol = "P25 CAI"

  -- Clear info column
  pinfo.cols.info:clear()

  -- Get Data Unit ID (DUID)
  local duid = bit.band(tvb(7, 1):uint(), 0xF)

  -- Set info column
  pinfo.cols.info:set(data_unit_ids[duid] or ("Unknown Data Unit (0x" .. string.format("%02x", duid) .. ")"))

  -- Create protocol tree
  local subtree = tree:add(p25cai, tvb())
  local offset = 0

  -- Add frame sync
  subtree:add(f.fs, tvb(offset, 6))
  offset = offset + 6

  -- Extract status symbols
  local extracted_tvb, outbound = extract_status_symbols(tvb, pinfo, subtree)

  -- Add NID fields
  local nid_item = subtree:add(f.nid, extracted_tvb(offset, 8))
  local nid_tree = nid_item
  nid_tree:add(f.nac, extracted_tvb(offset, 2))
  nid_tree:add(f.duid, extracted_tvb(offset, 2))
  offset = offset + 8

  -- Process by DUID type
  if duid == 0x0 then
    -- Header Data Unit
    local hdu_tvb = build_hdu_tvb(extracted_tvb, pinfo, offset)
    local du_item = subtree:add(f.hdu, hdu_tvb(0))
    local du_tree = du_item
    du_tree:add(f.mi, hdu_tvb(0, 9))
    du_tree:add(f.mfid, hdu_tvb(9, 1))
    du_tree:add(f.algid, hdu_tvb(10, 1))
    du_tree:add(f.kid, hdu_tvb(11, 2))
    local tgid = hdu_tvb(13, 2):uint()
    du_tree:add(f.tgid, tgid):append_text(string.format(" (0x%04x)", tgid))

  elseif duid == 0x3 then
    -- Terminator without Link Control
    -- Nothing left to decode

  elseif duid == 0x5 then
    -- Logical Link Data Unit 1
    -- TODO: source ID field (user id of the sending unit)
    -- TODO: destination ID field (user id of the intended recipient, only used for private voice messages)
    -- TODO: emergency indicator, 1 bit, 0x0 for routine, non-emergency condition, 0x1 for emergency condition
    local du_item = subtree:add(f.ldu1, extracted_tvb(offset))
    local du_tree = du_item
    dissect_voice(extracted_tvb, du_tree, offset)

    -- Link Control (LC) Word
    local lc_tvb = build_ldu_lc_tvb(extracted_tvb, pinfo, offset)
    dissect_lc(lc_tvb, du_tree)

    local lsd_tvb = build_ldu_lsd_tvb(extracted_tvb, pinfo, offset)
    du_tree:add(f.lsd, lsd_tvb(0, 2))

  elseif duid == 0x7 then
    -- Trunking Signaling Data Unit
    local tsdu_tvb = build_tsdu_tvb(extracted_tvb, pinfo, offset)
    local tsdu_offset = 0
    local last_block = 0

    -- print_tvb_bytes(tsdu_tvb, 0, 32, "tsdu_tvb")

    while tsdu_offset < tsdu_tvb:len() do
      -- Check if we have at least one more byte to read
      if tsdu_offset >= tsdu_tvb:len() then
        break
      end

      last_block = bit.rshift(tsdu_tvb(tsdu_offset, 1):uint(), 7)

      local mfid = tsdu_tvb(tsdu_offset + 1, 1):uint()

      local du_item = subtree:add(f.tsbk, tsdu_tvb(tsdu_offset, 12))
      local du_tree = du_item

      du_tree:add(f.lbf, tsdu_tvb(tsdu_offset, 1))
      local is_protected = tsdu_tvb(tsdu_offset, 1)
      ptbf_item = du_tree:add(f.ptbf, is_protected)


      if mfid > 1 then
        du_tree:add(f.unknown_opcode, tsdu_tvb(tsdu_offset, 1))
      elseif outbound == 1 then
        du_tree:add(f.osp_opcode, tsdu_tvb(tsdu_offset, 1))
      else
        du_tree:add(f.isp_opcode, tsdu_tvb(tsdu_offset, 1))
      end

      tsdu_offset = tsdu_offset + 1
      du_tree:add(f.mfid, tsdu_tvb(tsdu_offset, 1))
      tsdu_offset = tsdu_offset + 1
      du_tree:add(f.args, tsdu_tvb(tsdu_offset, 8))
      if outbound == 1 then
        -- TODO:fix
        local llid = tsdu_tvb(tsdu_offset+2, 2)
        du_tree:add(f.llid, llid)--:append_text(string.format(" (0x%04x)", tgid))
      end

      tsdu_offset = tsdu_offset + 8
      du_tree:add(f.crc, tsdu_tvb(tsdu_offset, 2))
      tsdu_offset = tsdu_offset + 2
      -- If this was the last block, we're done after processing it
      if last_block == 1 then
        break
      end
    end

  elseif duid == 0xA then
    -- Logical Link Data Unit 2
    local du_item = subtree:add(f.ldu2, extracted_tvb(offset))
    local du_tree = du_item
    dissect_voice(extracted_tvb, du_tree, offset)

    local es_tvb = build_ldu_es_tvb(extracted_tvb, pinfo, offset)
    dissect_es(es_tvb, du_tree)

    local lsd_tvb = build_ldu_lsd_tvb(extracted_tvb, pinfo, offset)
    du_tree:add(f.lsd, lsd_tvb(0, 2))

  elseif duid == 0xC then
    -- Packet Data Unit
    -- Not fully implemented, complex processing

  elseif duid == 0xF then
    -- Terminator Data Unit with Link Control
    local lc_tvb = build_term_lc_tvb(extracted_tvb, pinfo, offset)
    dissect_lc(lc_tvb, subtree)
  end

  return tvb:len()
end

----------------------------------------
-- The following creates the callback function for the dissector.
-- It's the same as doing "dns.dissector = function (tvbuf,pkt,root)"
-- The 'tvbuf' is a Tvb object, 'pktinfo' is a Pinfo object, and 'root' is a TreeItem object.

-- Main dissector function
--
-- Whenever Wireshark dissects a packet that our Proto is hooked into, it will call
-- this function and pass it these arguments for the packet it's dissecting.
--
---@param tvb userdata Tvb object (Tapped Virtual Buffer represents captured packet data)
---@param pinfo userdata Pinfo object (Packet info)
---@param root userdata TreeItem object (Root of tree)
function p25cai.dissector(tvb, pinfo, root)
  local ok, err = pcall(dissect, tvb, pinfo, root)
  if not ok then
    dprint("ERROR: dissect() returned false, err=" .. err)
  else
    dprint("dissect() returned true")
  end
end

-- Register the dissector
local udp_port = DissectorTable.get("udp.port")
udp_port:add(23456, p25cai)

local dissector_info = {
  version = "0.0.1",
  author = "Ryan A. Chapman",
  repository = "https://github.com/ryanchapman/p25_wireshark"
}

set_plugin_info(dissector_info)
