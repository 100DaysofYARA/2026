rule tool_localtonet_gen
{
    meta:
        description = "Detects Localtonet tunneling tool"
        author = "@t3ft3lb"
        date = "2026-03-13"
        reference = "https://localtonet.com/"
        hash1 = "ba7b706f57179781a484017d184e765b29614111d026de00085b333a57da4a3d" // PE32+
        hash2 = "6f90a226f643e815d9668ac6a9cea82e62d2d0a81ae88ce2941aca19cf15e5b9" // ELF64
        hash3 = "c4a79c9f381acb36542d1555722e472b426b2147a1e8dcaf34cdc9b207c21863" // Mach-O64

    strings:
        $x = "localtonet" ascii fullword

        $s0 = "CheckUserTunnelIsCorrect" ascii fullword
        $s1 = "LocalHTTP" wide fullword
        $s2 = "LocalSOCKS" wide fullword
        $s3 = "tunnelled via Proxy" wide fullword
        $s4 = "authtoken YOUR_TOKEN" wide fullword
        $s5 = "Please Enter AuthToken or PIN" wide fullword

    condition:
        (
         (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) or
         uint32(0) == 0x464C457F or
         uint32(0) == 0xCEFAEDFE or
         uint32(0) == 0xCFFAEDFE or
         uint32(0) == 0xFEEDFACE or
         uint32(0) == 0xFEEDFACF
        ) and
        filesize > 170MB and filesize < 200MB and 
        #x > 100 and all of ($s*)
}