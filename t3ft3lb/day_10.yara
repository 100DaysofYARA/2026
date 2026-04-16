rule ta_watch_wolf_darkwatchman_js_loader
{
    meta:
        description = "Detects Watch Wolf (Hive0117) DarkWatchman JS loader"
        author = "@t3ft3lb"
        date = "2026-01-10"
        reference_1 = "https://cyble.com/blog/sophisticated-darkwatchman-rat-spreads-through-phishing-sites/"
        reference_2 = "https://attack.mitre.org/software/S0673/"
        hash1 = "cc1fd0e91c60bc8ce24e934d0401faf851077b08554da4d60be59ecce4b71eef"
        hash2 = "86726ca3e63b4a6cb7112803da4cd1c7c7a337bc7d560bb201137e2d1b48b87d"
        hash3 = "53c8d2f87e9576646d5ed60587147ef16463757ba9128282b63519d6aefaf3ad"

    strings:
        $s0 = "String.fromCharCode[String.fromCharCode" ascii fullword
        $s1 = "new Array();" ascii fullword
        $s2 = "for(var" ascii fullword
        
        $x = "\x0D\x0Acatch(e)\x0D\x0A" ascii fullword

    condition:
        uint16(0) == 0x0A0D and
        filesize > 30KB and filesize < 80KB and
        all of ($s*) and $x in (filesize-25..filesize)
}