rule ta_cavalry_werewolf_foalshell_go
{
    meta:
        description = "Detects Cavalry Werewolf (YoroTrooper, Tomiris) FoalShell Go reverse shell"
        author = "@t3ft3lb"
        date = "2026-03-19"
        reference_1 = "https://bi.zone/eng/expertise/blog/cavalry-werewolf-atakuet-rossiyu-cherez-doveritelnye-otnosheniya-mezhdu-gosudarstvami/"
        reference_2 = "https://news.drweb.com/show/?i=15078&lng=en&c=5"
        hash1 = "6b290953441b1c53f63f98863aae75bd8ea32996ab07976e498bad111d535252"
        hash2 = "ab0ad77a341b12cfc719d10e0fc45a6613f41b2b3f6ea963ee6572cf02b41f4d"
        hash3 = "fbf7107f46f8a2395c77714a8cb86466f8a893732b74f9fe632e441ad58b1d42"
        
    strings:
        $go = "Go build" ascii

        $s0 = "C:/source/repos/ggg" ascii fullword
        $s1 = "os/exec.(*Cmd).Run" ascii fullword
        $s2 = "os/exec.Command" ascii fullword
        $s3 = "cmd.exewindowsrunning" ascii

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and
        filesize > 1MB and filesize < 4MB and
        all of them
}