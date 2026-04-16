rule mlwr_silentrift_loader
{
    meta:
        description = "Detects SilentRift Loader"
        author = "@t3ft3lb"
        date = "2026-02-14"
        reference_1 = "https://x.com/DarkWebInformer/status/1971720878020088260"
        reference_2 = "https://blog.thread-community.net/HzkZp8vDKwP"
        hash = "d2c1f488cfa705b0410aecd71533af165257f94b1247b34b72e0a11d71580e3e"

    strings:
        $rust = "rustc" ascii fullword

        $pdb = "silentrift_loader.pdb" ascii fullword
        
        $s0 = "SilentRiftSalt1234NonceSalt1234" ascii fullword
        $s1 = "IsDebuggerPresent" ascii fullword
        $s2 = ".llvm./rust/deps" ascii fullword

        $h0 = { B9 01 00 00 00 BA 5B 02 01 00 }
        $h1 = { B9 5B 02 01 00 BA 01 00 00 00 }
        $h2 = { 48 B8 34 36 37 32 37 38 34 33 }
        $h3 = { 48 B9 4F 8A 22 AF 48 72 0F D2 }
        $h4 = { 49 83 C6 04 83 E0 07 C1 E0 12 C1 E3 06 83 E2 3F }
        $h5 = { 48 BA D9 7E EF F5 8E 9A F1 84 48 31 D0 BA 02 D8 22 9C }
        $h6 = { C1 E8 0A 0D 00 D8 00 00 81 E3 FF 03 00 00 81 CB 00 DC 00 00 }
        $h7 = { C1 E9 0A 81 C9 00 D8 00 00 81 E6 FF 03 00 00 81 CE 00 DC 00 00 }
        $h8 = { BA E8 03 00 00 48 F7 E2 89 C9 48 69 C9 83 DE 1B 43 48 C1 E9 32 48 01 C1 48 83 D2 00 31 C0 41 B8 83 03 00 00 }

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and
        filesize > 100KB and filesize < 500KB and
        #rust > 10 and ($pdb or (2 of ($s*) and 4 of ($h*)))
}