rule hacktool_gsnetcat_gsocket_gen
{
    meta:
        description = "Detects gs-netcat (GSocket - The Global Socket Tookit) hacktool"
        author = "@t3ft3lb"
        date = "2026-02-26"
        reference = "https://www.gsocket.io/"
        hash1 = "1756b5d536035347ffbe2dbf364906fd66b981e846413723012fb06c8f820d3f" // PE32+
        hash2 = "55d141bb2f62c527c3fea3413b8429fed7d52633d0b123b5e611bfa42165229f" // ELF64
        hash3 = "3ef3f8a8f83533d0aa5c6087579b532e244fa2d9ddeadc99cc0de57b8d3e6906" // Mach-O64

    strings:
        $x0 = "GSOCKET_CONFIG" fullword ascii
        $x1 = "gs-netca" ascii

        $s0 = "gs.thc.org" fullword ascii
        $s1 = "GSRN" fullword ascii
        $s2 = "gse" fullword ascii
        $s3 = "gsb" fullword ascii
        $s4 = "gsocket" fullword ascii nocase
        $s5 = "gs-netcat" fullword ascii nocase

        $h = {(47 53 5F | 67 73 5F)} // GS_ or gs_

    condition:
        (
         (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) or
         uint32(0) == 0x464C457F or
         uint32(0) == 0xCEFAEDFE or
         uint32(0) == 0xCFFAEDFE or
         uint32(0) == 0xFEEDFACE or
         uint32(0) == 0xFEEDFACF
        ) and
        filesize > 100KB and filesize < 5MB and
        (any of ($x*) or (5 of ($s*) and #h > 5))
}