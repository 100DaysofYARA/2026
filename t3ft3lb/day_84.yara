rule hacktool_frp_gen
{
    meta:
        description = "Detects frp (Fast Reverse Proxy) tunneling hacktool"
        author = "@t3ft3lb"
        date = "2026-03-25"
        reference = "https://github.com/fatedier/frp"
        hash1 = "6e89b763cd4dd79f0c3082f09813efbd3dac4374a95455fe86ed27c363309a45" // PE32+, frpc
        hash2 = "8ebccff7576278a63a137ca69b47d365782716fc5e7a9292485986234deaf8dc" // ELF64, frpc
        hash3 = "dd5480c8f53c0454705a3d7b6aa1211ef394e06c832878a7c4a87fe35181f06f" // Mach-O64, frps
    
    strings:
        $go = "Go build" ascii

        $x = "/frp/" ascii

        $s0 = "frpc/main.go" ascii fullword
        $s1 = "frps/main.go" ascii fullword
        $s2 = "the configuration file is not specified" ascii
        $s3 = "the configuration file %s syntax is ok" ascii
        $s4 = "config file of frp" ascii
        $s5 = "version of frp" ascii

    condition:
        (
         (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) or
         uint32(0) == 0x464C457F or
         uint32(0) == 0xCEFAEDFE or
         uint32(0) == 0xCFFAEDFE or
         uint32(0) == 0xFEEDFACE or
         uint32(0) == 0xFEEDFACF
        ) and
        filesize > 7MB and filesize < 22MB and
        $go and $x and 4 of ($s*)
}