rule ta_nebulous_werewolf_rustywater_rat
{
    meta:
        description = "Detects Nebulous Werewolf (MuddyWater) RustyWater RAT"
        author = "@t3ft3lb"
        date = "2026-01-18"
        reference = "https://www.cloudsek.com/blog/reborn-in-rust-muddywater-evolves-tooling-with-rustywater-implant"
        hash1 = "7523e53c979692f9eecff6ec760ac3df5b47f172114286e570b6bba3b2133f58"
        hash2 = "a2001892410e9f34ff0d02c8bc9e7c53b0bd10da58461e1e9eab26bdbf410c79"
        hash3 = "e61b2ed360052a256b3c8761f09d185dad15c67595599da3e587c2c553e83108"

    strings:
        $rust = "rustc" ascii fullword
        
        $s0 = "00010203040506070809101112131415161718192021222324252627282930313233343536373839404142434445464748495051525354555657585960616263646566676869707172737475767778798081828384858687888990919293949596979899" ascii
        $s1 = "No detections found" ascii
        $s2 = "PROGRAMDATA" ascii
        $s3 = "HTTP_PROXYhttp_proxy" ascii fullword
        $s4 = "AvastAvast AntivirusAVAST Software\\AvastAVAST Software\\Persistent Data\\Avast\\avast5.ini" ascii fullword
        $s5 = "AVGAVG AntivirusAVG\\AntivirusAVG\\Antivirus\\Log" ascii fullword
        
        $m0 = "modules\\detect_av.rs" ascii fullword
        $m1 = "modules\\information.rs" ascii fullword
        $m2 = "modules\\persist.rs" ascii fullword
        $m3 = "modules\\interface.rs" ascii fullword

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and
        filesize > 1MB and filesize < 3MB and
        #rust > 10 and 4 of ($s*) and 2 of ($m*)
}