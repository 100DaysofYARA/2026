rule ta_subtle_werewolf_krustyloader_gen
{
    meta:
        description = "Detects Subtle Werewolf (QuietCrabs, UTA0178, UNC5221) KrustyLoader"
        author = "@t3ft3lb"
        date = "2026-04-03"
        reference_1 = "https://www.synacktiv.com/publications/krustyloader-rust-malware-linked-to-ivanti-connectsecure-compromises"
        reference_2 = "https://global.ptsecurity.com/en/research/pt-esc-threat-intelligence/dragons-in-thunder/"
        hash1 = "c7ddd58dcb7d9e752157302d516de5492a70be30099c2f806cb15db49d466026"
        hash2 = "bdb9a4c1532b5ba38fd8a9c01430f2db4cd74ee0123deaa65cfdf61196fc7d3a"

    strings:
        $rust = "rustc" ascii fullword

        $x0 = "TOKIO_WORKER_THREADS" ascii
        $x1 = /\|{50,100}/ ascii

        // PE
        $s0 = "[-]PE Signature was not 0x4550" ascii fullword
        $s1 = "[-]DOS image header magic was not 0x5a4d!" ascii fullword
        $s2 = "/downloads/" ascii
        // ELF
        $s3 = "/tmp/" ascii
        $s4 = "/proc/self/exe" ascii fullword
        $s5 = "/etc/resolv.conf" ascii fullword

    condition:
        (
         (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) or
         uint32(0) == 0x464C457F
        ) and
        filesize > 600KB and filesize < 3MB and
        $rust and all of ($x*) and 3 of ($s*)
}