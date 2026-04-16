rule ta_lenient_wolf_ak47dns_backdoor
{
    meta:
        description = "Detects Lenient Wolf (Storm-2603, GOLD SALEM) AK47DNS backdoor"
        author = "@t3ft3lb"
        date = "2026-03-21"
        reference_1 = "https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/"
        reference_2 = "https://unit42.paloaltonetworks.com/ak47-activity-linked-to-sharepoint-vulnerabilities/"
        hash1 = "1eb914c09c873f0a7bcf81475ab0f6bdfaccc6b63bf7e5f2dbf19295106af192"
        hash2 = "b5a78616f709859a0d9f830d28ff2f9dbbb2387df1753739407917e96dadf6b0"
        hash3 = "c27b725ff66fdfb11dd6487a3815d1d1eba89d61b0e919e4d06ed3ac6a74fe94"
        
    strings:
        $pdb = "ak47c2\\dnsclinet" ascii fullword

        $s0 = "unknown.local" ascii fullword
        $s1 = "Slept for %d seconds" ascii fullword
        $s2 = "cmd.exe /c %s 2>&1" ascii fullword
        $s3 = "Failed to execute command" ascii fullword
        $s4 = "Command executed with no output" ascii fullword
        $s5 = "s%st%04zup%04zu" ascii fullword
        $s6 = "fragment_received" ascii fullword
        $s7 = "result_received" ascii fullword
        $s8 = "VHBD@H" ascii fullword

        $h0 = { 49 F7 E1 49 FF C1 48 C1 EA 02 }
        $h1 = { 48 BB 8F E3 38 8E E3 38 8E E3 }

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and
        filesize > 15KB and filesize < 200KB and
        $pdb or (5 of ($s*) and any of ($h*))
}