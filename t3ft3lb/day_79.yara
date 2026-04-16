rule hacktool_regeorg_gen
{
    meta:
        description = "Detects reGeorg hacktool (tunnel web shell and socks server)"
        author = "@t3ft3lb"
        date = "2026-03-20"
        reference_1 = "https://github.com/sensepost/reGeorg"
        reference_2 = "https://github.com/sensepost/reGeorg/blob/master/reGeorgSocksProxy.py"
        hash1 = "c1f43b7cf46ba12cfc1357b17e4f5af408740af7ae70572c9cf988ac50260ce1" // tunnel.aspx
        hash2 = "730d112cf4ed9a08d1b80cb2fd3c3ce943febbdf2f43b0c69e24b74d298e2d1e" // tunnel.js
        hash3 = "b1a6bdd3fdf5c80c8de451567cf6eb7b4885d84e1b5d5399576a380ce82d5c8e" // reGeorgSocksProxy.py
        
    strings:
        $x0 = "every office needs a tool like Georg" ascii fullword
        $x1 = "Georg says, 'All seems fine'" ascii fullword
        $x2 = "reGeorg" ascii fullword
        $x3 = "X-ERROR" ascii fullword

    condition:
        filesize > 2KB and filesize < 20KB and
        2 of ($x*)
}