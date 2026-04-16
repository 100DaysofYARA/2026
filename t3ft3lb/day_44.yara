rule hacktool_chisel_gen
{
    meta:
        description = "Detects Chisel TCP/HTTP tunneling hacktool"
        author = "@t3ft3lb"
        date = "2026-02-13"
        reference = "https://github.com/jpillora/chisel"
        hash1 = "3518b109468241d258fdbf07f3558ecd079cdbc596c69b1772546a7fa548fbbd" // PE32+
        hash2 = "b84450974bd3f1fc5dc09ec0edeec50647df81716e305ef391c9115c751aab17" // ELF64
        hash3 = "bdf3b47e7d01960b36b81c78f47bad521beeb8f6bec5ffa93f053740d119e99e" // Mach-O64

    strings:
        $x0 = "jpillora" ascii
        $x1 = "/chisel/" ascii
        $x2 = "chisel-v" ascii

        $s0 = "KEY_FILE" ascii
        $s1 = "Retrying in %s..." ascii
        $s2 = "Handshaking..." ascii
        $s3 = "Sending config" ascii
        $s4 = "Invalid authentication for username: %s" ascii
        $s5 = "Fingerprint %s" ascii
        $s6 = "-clientGive up-server" ascii

        $ws1 = "Sec-WebSocket-Key" ascii
        $ws2 = "Sec-WebSocket-Protocol" ascii
        $ws3 = "Sec-Websocket-Version" ascii
        $ws4 = "Sec-Websocket-Extensions" ascii
        
    condition:
        (
         (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) or
         uint32(0) == 0x464C457F or
         uint32(0) == 0xCEFAEDFE or
         uint32(0) == 0xCFFAEDFE or
         uint32(0) == 0xFEEDFACE or
         uint32(0) == 0xFEEDFACF
        ) and
        filesize > 6MB and filesize < 12MB and
        any of ($x*) and 3 of ($s*) and 3 of ($ws*)
}