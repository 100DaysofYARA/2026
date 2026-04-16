rule tool_velociraptor_with_config_gen
{
    meta:
        description = "Detects Velociraptor (DFIR tool) binaries with embedded configuration"
        author = "@t3ft3lb"
        date = "2026-03-31"
        reference_1 = "https://rt-solar.ru/solar-4rays/blog/4559/"
        reference_2 = "https://t.me/ptescalator/577"
        hash1 = "3e92b6e59a858ef67860fd8cb122d7a0f1908e96828d0e051cc8b7097896a7a5" // Gambling Hyena
        hash2 = "639bf088bcd9a1ac21afbac3438fe84eb1d686c24fccfc8968ed0f9ede2540cf" // Feral Wolf

    strings:
        $go = "Go build" ascii

        $s0 = "velociraptor" ascii fullword
        $s1 = "azure_upload.go" ascii fullword
        $s2 = "config_merge.go" ascii fullword
        $s3 = "analysis_target.go" ascii fullword

        $config = "###<Begin Embedded Config>\x0A\x78\x9C" ascii fullword

    condition:
        (
         (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) or
         uint32(0) == 0x464C457F or
         uint32(0) == 0xCEFAEDFE or
         uint32(0) == 0xCFFAEDFE or
         uint32(0) == 0xFEEDFACE or
         uint32(0) == 0xFEEDFACF
        ) and
        filesize > 50MB and filesize < 100MB and
        all of them
}