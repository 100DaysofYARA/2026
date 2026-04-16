rule hacktool_glider_gen
{
    meta:
        description = "Detects glider tunneling hacktool"
        author = "@t3ft3lb"
        date = "2026-03-28"
        reference = "https://github.com/nadoo/glider"
        hash1 = "2e8a4fb54275c275ef8a47585edd804593893edcde2a1003af709343f4e0c944" // PE32+
        hash2 = "20262a67e65c03e0f34b0ff43ca4c72f3d201908c5b24b4ff8680989d6e53b20" // ELF64
        hash3 = "d23b578714fb93ab820ed222a2092155dcf11a0b4325d7f7514e268d3ab4a888" // Mach-O64
    
    strings:
        $go = "Go build" ascii

        $s0 = "nadoo" fullword ascii
        $s1 = "glider" fullword ascii
        $s2 = "/etc/glider/glider.conf" fullword ascii
        $s3 = "conflag.newStringSliceUniqValue" fullword ascii
        $s4 = "rule.NewConfFromFile" fullword ascii
        $s5 = "[trojanc] create instance error: %s" ascii
        $s6 = "[ss] PickCipher for '%s', error: %s" ascii
        $s7 = "[vmess] error in ResolveUDPAddr: %v" ascii

    condition:
        (
         (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) or
         uint32(0) == 0x464C457F or
         uint32(0) == 0xCEFAEDFE or
         uint32(0) == 0xCFFAEDFE or
         uint32(0) == 0xFEEDFACE or
         uint32(0) == 0xFEEDFACF
        ) and
        filesize > 5MB and filesize < 10MB and
        $go and 3 of ($s*)
}