rule hacktool_ligolong_agent_gen
{
    meta:
        description = "Detects Ligolo-ng agent, a tunneling and pivoting hacktool"
        author = "@t3ft3lb"
        date = "2026-04-10"
        reference = "https://github.com/nicocha30/ligolo-ng"
        hash1 = "4b41f36f82db6da8767a0a1c2997c8242d80b2d10a8f1d28c252a9306ec152b5" // PE32+
        hash2 = "ffc211e8bc6cf0a4f3699794f4327f979e1c963cff78c63d0c3f9508884263fd" // ELF64
        hash3 = "0602c1d04f9cb6b47391ac0002df8da3dfe574bedeff21d6a6a25e8368f1f91f" // Mach-O64
    
    strings:
        $go = "Go build" ascii

        $x0 = "nicocha30" ascii
        $x1 = "ligolo-ng" ascii
        $x2 = "/cmd/agent/main.go" ascii
        $x3 = "/pkg/agent/" ascii
        
        $s0 = "TLS Certificate fingerprint is: %X" ascii
        $s1 = "Got connection from: %s" ascii
        $s2 = "please, specify the target host user -connect host:port" ascii
        $s3 = "Invalid connect address, please use https://host:port for websocket or host:port for tcp" ascii
        $s4 = "invalid proxy address, please use socks5://host:port" ascii
        $s5 = "Can't use http-proxy with direct (tcp) connection. Only with websocket"
        $s6 = "invalid socks5 address, please use socks://host:port" ascii
        $s7 = "invalid cert fingerprint: %v" ascii
        $s8 = "certificate does not match fingerprint: %X != %X" ascii
        $s9 = "Websocket connection established" ascii

    condition:
        (
         (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) or
         uint32(0) == 0x464C457F or
         uint32(0) == 0xCEFAEDFE or
         uint32(0) == 0xCFFAEDFE or
         uint32(0) == 0xFEEDFACE or
         uint32(0) == 0xFEEDFACF
        ) and
        filesize > 4MB and filesize < 9MB and
        $go and 2 of ($x*) and 6 of ($s*)
}