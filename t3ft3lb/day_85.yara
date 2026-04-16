rule tool_ngrok_go_gen
{
    meta:
        description = "Detects ngrok (Go) tunneling tool"
        author = "@t3ft3lb"
        date = "2026-03-26"
        reference = "https://ngrok.com/"
        hash1 = "203569f48ded9168ce69ca166ec7bb026149afb10181f8e230526bcfbff5a5df" // PE32+
        hash2 = "b26b4cefb478a5b7293a782baca7adaa17cedaf917c69dff3e9bc8b957c1a11b" // ELF64
        hash3 = "2069424920c9914244ed0d48326bba3ba83095c8be56b4f82913469d3ddafb5d" // Mach-O64
    
    strings:
        $go = "Go build" ascii

        $s0 = "ngrok" fullword ascii
        $s1 = "/cli/api_root_documented_only.go"
        $s2 = "https://s3.amazonaws.com/dns.ngrok.com/tunnel.json" ascii
        $s3 = "ngrokService" ascii
        $s4 = "HTTPRoundTrip_KeyVal" ascii
        $s5 = "go.ngrok.com" ascii

    condition:
        (
         (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) or
         uint32(0) == 0x464C457F or
         uint32(0) == 0xCEFAEDFE or
         uint32(0) == 0xCFFAEDFE or
         uint32(0) == 0xFEEDFACE or
         uint32(0) == 0xFEEDFACF
        ) and
        filesize > 25MB and filesize < 60MB and
        $go and 3 of ($s*)
}

