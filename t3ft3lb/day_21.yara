rule ta_cavalry_werewolf_jlorat
{
    meta:
        description = "Detects Cavalry Werewolf (YoroTrooper, Tomiris) JLORAT"
        author = "@t3ft3lb"
        date = "2026-01-21"
        reference1 = "https://securelist.com/tomiris-new-tools/118143/"
        reference2 = "https://blog.talosintelligence.com/attributing-yorotrooper/"
        hash1 = "1c7865b617ac0e01542077d3474d17d7c944a74b91116aef69c229e77df99f1f"
        hash2 = "1828e2df0ad76ea503af7206447e40482669bb25624a60b0f77743cd70f819f6"

    strings:
        $rust = "rustc" ascii fullword

        $pdb = "jlo.pdb" ascii fullword

        $s0 = "src\\moduls\\get_info.rs" ascii
        $s1 = "src\\moduls\\reqw.rs" ascii
        $s2 = "src\\moduls\\sendfile.rs" ascii
        $s3 = "src\\moduls\\screen.rs" ascii
        $s4 = "src\\func\\cmd_pars.rs" ascii
        $s5 = "SELECT * FROM MSAcpi_ThermalZoneTemperature" wide fullword

        $c0 = "cmdupload" ascii fullword
        $c1 = "query" ascii fullword
        $c2 = "upload" ascii fullword
        $c3 = "screen" ascii fullword

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and
        filesize > 500KB and filesize < 2MB and
        #rust > 10 and ($pdb or (2 of ($s*) and 2 of ($c*)))
}