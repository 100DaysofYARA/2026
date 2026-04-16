rule ta_sticky_werewolf_msc_dropper
{
    meta:
        description = "Detects Sticky Werewolf (Angry Likho, PhaseShifters) MSC dropper"
        author = "@t3ft3lb"
        date = "2026-03-06"
        reference = "https://habr.com/ru/companies/F6/news/845766/"
        hash1 = "47486ec6627fced4663d52c408f85f6a74cb9f256b4ef111c66e2bc990b271f9"
        hash2 = "f90627948bd44ebf67011fd6f0e55f8da6816c18dba7f535aad316bab2c8a3b4"

    strings:
        $x0 = "MMC_ConsoleFile" ascii fullword
        $x1 = "{C96401CC-0E17-11D3-885B-00C04F72C717}" ascii fullword

        $s0 = ".msc&quot;&amp;" ascii
        $s1 = ".ms&quot;?`)" ascii
        $s2 = ".cmD&amp;!o!" ascii

    condition:
        uint32(0) == 0x6D783F3C and
        filesize > 100KB and filesize < 10MB and
        $x0 and #x1 > 3 and 2 of ($s*)
}