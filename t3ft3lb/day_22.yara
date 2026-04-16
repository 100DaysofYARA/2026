import "pe"

rule mlwr_shadowrelay_backdoor
{
    meta:
        description = "Detects ShadowRelay backdoor"
        author = "@t3ft3lb"
        date = "2026-01-22"
        reference = "https://rt-solar.ru/solar-4rays/blog/6328/"
        hash = "541628370c4d4f64468021bd83414efa9ee1634554acf29055c6c1dfa601a5e5"

    strings:
        $s0 = "wmic path win32_computersystem get model /value" ascii fullword
        $s1 = "--------job:%s\n" ascii fullword
        $s2 = "S&j0$" ascii fullword
        $s3 = "*#06#C" ascii fullword

        $c0 = "mode" ascii fullword
        $c1 = "proto" ascii fullword
        $c2 = "svri" ascii fullword
        $c3 = "svrp" ascii fullword
        $c4 = "reconnintv" ascii fullword      
        $c5 = "enctype" ascii fullword
        $c6 = "aeskey" ascii fullword
        $c7 = "rsapubkey" ascii fullword
        $c8 = "rsaprikey" ascii fullword
        $c9 = "antidebug" ascii fullword
        $c10 = "autostart" ascii fullword
        $c11 = "portreuse" ascii fullword
        $c12 = "transip" ascii fullword
        $c13 = "reuseport" ascii fullword
        $c14 = "envpara" ascii fullword

        $p0 = "plugin_deinit" ascii fullword
        $p1 = "plugin_init" ascii fullword
        $p2 = "plugin_task" ascii fullword
        $p3 = "plugin_exec" ascii fullword
        $p4 = "plugin_mq" ascii fullword

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and
        filesize > 1MB and filesize < 4MB and
        (
            (2 of ($s*) and 7 of ($c*) and 3 of ($p*)) or
            pe.imphash() == "26be21847eabafbcf20a4e92427dd55f"
        )
}