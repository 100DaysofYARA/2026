rule tool_tun2socks_gen
{
    meta:
        description = "Detects tun2socks tool used for network traffic tunneling via SOCKS proxy"
        author = "@t3ft3lb"
        date = "2026-04-04"
        reference = "https://github.com/xjasonlyu/tun2socks"
        hash1 = "bc5827ca00c7f312125365e8669794fffdbdf1cb0efa948cddd94a0c800c8c31" // PE32+
        hash2 = "da49c8eeebb36b0ece65e4f565328fc5551bd597e6e9f1c83d3e8346f4081710" // ELF64
        hash3 = "476bc470be43d88767ed469b2e6a892917b7b31e86b0cd0c35e1486d35b97185" // Mach-O64

    strings:
        $go = "Go build" ascii

        $s0 = "tun2socks" fullword ascii
        $s1 = "xjasonlyu" fullword ascii
        $s2 = "engine.parseShadowsocks" fullword ascii
        $s3 = "Set firewall MARK (Linux only)" ascii
        $s4 = "Use this proxy [protocol://]host[:port]" ascii
        $s5 = "Failed to unmarshal config file '%s': %v" ascii

    condition:
        (
         (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) or
         uint32(0) == 0x464C457F or
         uint32(0) == 0xCEFAEDFE or
         uint32(0) == 0xCFFAEDFE or
         uint32(0) == 0xFEEDFACE or
         uint32(0) == 0xFEEDFACF
        ) and
        filesize > 7MB and filesize < 12MB and
        $go and 4 of ($s*)
}