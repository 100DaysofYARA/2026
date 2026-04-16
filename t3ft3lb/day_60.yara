rule tool_wstunnel_gen
{
    meta:
        description = "Detects Wstunnel tunneling tool"
        author = "@t3ft3lb"
        date = "2026-03-01"
        reference = "https://github.com/erebe/wstunnel"
        hash1 = "9dda789b85fce6294f91a79b7271a93de36dfcef21fc680dc2bf4235141e47df" // PE32+
        hash2 = "c2f6198fde46a064e7b1a703fbe4be3cc774bd29bbc738782eb5855492d18717" // ELF64
        hash3 = "4c8c5a32ae9899efc0a59fc705219ee0dcce38d09d4bb9f1e2425f713ecc7378" // Mach-O64

    strings:
        $rust = "rustc" ascii fullword

        $s0 = "wstunnel" ascii fullword
        $s1 = "wss://0.0.0.0:8080" ascii fullword
        $s2 = "reverse_tunnel.rs" ascii fullword
        $s3 = "handler_websocket.rs" ascii fullword
        $s4 = "l4_transport_stream.rs" ascii fullword
        $s5 = "config_reloader.rs" ascii fullword
        $s6 = "udp_server.rs" ascii fullword
        $s7 = "Example: For websocket with TLS wss" ascii fullword

    condition:
        (
         (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) or
         uint32(0) == 0x464C457F or
         uint32(0) == 0xCEFAEDFE or
         uint32(0) == 0xCFFAEDFE or
         uint32(0) == 0xFEEDFACE or
         uint32(0) == 0xFEEDFACF
        ) and
        filesize > 7MB and filesize < 15MB and
        #rust > 10 and 6 of ($s*)
}
