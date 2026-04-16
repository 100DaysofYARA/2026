import "pe"

rule ta_insatiable_werewolf_diaoyu_loader
{
    meta:
        description = "Detects Insatiable Werewolf (UNC6619, TGR-STA-1030) Diaoyu loader"
        author = "@t3ft3lb"
        date = "2026-02-12"
        reference = "https://unit42.paloaltonetworks.com/shadow-campaigns-uncovering-global-espionage/"
        hash = "23ee251df3f9c46661b33061035e9f6291894ebe070497ff9365d6ef2966f7fe"

    strings:
        $url = "padeqav/WordPress/refs/heads/master/wp-includes/images" ascii fullword

        $s0 = "DiaoYu" wide fullword
        $s1 = "pic1.png" ascii fullword
        $s2 = "\\Links\\\x00.docx" ascii fullword
        $s3 = "\\Videos\\msedgeupdate.dll" ascii fullword
        $s4 = "\\Videos\\msedgeupdate.exe" ascii fullword
        $s5 = "RQVwlToEMOyk1QqOWICpqSesrfomtmIR" ascii fullword
        $s6 = "05343A1E2A3B3B212C201505463E3503051C" ascii fullword
        $s7 = "7D3C391442200120392116084334023A353C2B0418344B04131440424E1E39267468" ascii fullword

        $av0 = "avp.exe" ascii fullword
        $av1 = "SentryEye.exe" ascii fullword
        $av2 = "EPSecurityService.exe" ascii fullword
        $av3 = "SentinelUI.exe" ascii fullword
        $av4 = "NortonSecurity.exe" ascii fullword

        $h = { 40 80 FE 09 8D 46 ?? 0F B6 D0 0F 4E D6 C0 E2 04 41 8D 40 ?? 41 80 F8 09 }

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and
        filesize > 100KB and filesize < 200KB and
        (
            (#url > 2 and 4 of ($s*) and 2 of ($av*) and $h) or
            pe.imphash() == "854e2b63200cb1f1fd77532cbea7f503"
        )
}