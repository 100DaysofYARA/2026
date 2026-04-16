rule mlwr_lucidrook_stager
{
    meta:
        description = "Detects LucidRook stager"
        author = "@t3ft3lb"
        date = "2026-04-09"
        reference = "https://blog.talosintelligence.com/new-lua-based-malware-lucidrook/"
        hash1 = "edb25fed9df8e9a517188f609b9d1a030682c701c01c0d1b5ce79cba9f7ac809"
        hash2 = "0305e89110744077d8db8618827351a03bce5b11ef5815a72c64eea009304a34"

    strings:
        $s0 = "RustBacktraceMutex00000000" ascii fullword
        $s1 = "unsupported Zip archive:" ascii fullword
        $s2 = "FTP InvalidAddress:" ascii fullword
        $s3 = "DismCore.pdb" ascii fullword
        $s4 = "LUA_NOENV" ascii fullword
        $s5 = "src\\process\\run_process.rs" ascii
        $s6 = "\x1BLua" ascii
        
        $h0 = { 48 C1 E6 38 49 C1 E3 30 49 09 F3 49 C1 E2 28 4D 09 DA 49 C1 E1 20 }
        $h1 = { C1 E8 1B 31 D0 BA 18 45 00 00 29 C2 0F B7 C2 35 82 76 00 00 }
        $h2 = { C1 E1 18 41 C1 E0 10 41 09 C8 C1 E0 08 }

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and
        filesize > 1MB and filesize < 3MB and
        6 of ($s*) and 2 of ($h*)
}