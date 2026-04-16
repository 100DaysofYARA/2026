rule hacktool_gost_gen
{
    meta:
        description = "Detects gost (GO Simple Tunnel) tunneling hacktool"
        author = "@t3ft3lb"
        date = "2026-03-14"
        reference = "https://github.com/ginuerzh/gost"
        hash1 = "38fbf1cc4869947ebddd419b3ed0a84447db3401777237f3782b0682f6615987" // PE32+
        hash2 = "fa80a1e458cb1e07e0562a725b691a1314b0f2407403c54f6bd8c9ef9e010996" // ELF64
        hash3 = "c772c4b1316cd55867a3fb18068219b0c44eccdc924b4768995dba8ad045a4da" // Mach-O64

    strings:
        $go = "Go build" ascii

        $s0 = "/gost/" ascii
        $s1 = "/gost.go" ascii
        $s2 = "/cfg.go" ascii
        $s3 = "/peer.go" ascii
        $s4 = "/route.go" ascii
        $s5 = "ginuerzh" ascii fullword
        $s6 = "socks5UDPTunnelConn" ascii fullword
        $s7 = "HTTPTunnelHandlerOption" ascii fullword
        $s8 = "ProxyAgentHandlerOption" ascii fullword

    condition:
        (
         (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) or
         uint32(0) == 0x464C457F or
         uint32(0) == 0xCEFAEDFE or
         uint32(0) == 0xCFFAEDFE or
         uint32(0) == 0xFEEDFACE or
         uint32(0) == 0xFEEDFACF
        ) and
        filesize > 10MB and filesize < 16MB and
        $go and 6 of ($s*)
}