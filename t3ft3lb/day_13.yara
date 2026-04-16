rule ta_core_werewolf_rust_dropper
{
    meta:
        description = "Detects Core Werewolf (PseudoGamaredon, Awaken Likho) dropper written in Rust"
        author = "@t3ft3lb"
        date = "2026-01-13"
        reference_1 = "https://amonitoring.ru/article/novye_modifikatsii_vpo_svyazannye_s_apt_gruppirovkoy_core_werewolf/"
        reference_2 = "https://www.f6.ru/blog/apt-autumn/"
        hash1 = "6e868986aa6adba3a8ecc8569e8e2bfda270efd3469580b8f1dc202bb9b2fc4c"
        hash2 = "f802f04b9d835060bebfdacf235b219163c32321837a2d78f60ea20a2d816f29"
        hash3 = "7b6458c23530adcdea129efb6f6683b32659e772b33cc06eeb0fc076816dfbe8"

    strings:
        $rust = "rustc" ascii fullword

        $x0 = "cscript.exe" ascii fullword
        $x1 = "cmdstart" ascii fullword
        $x2 = "powershellcmd" ascii fullword

        $s0 = ".pdfPK" ascii
        $s1 = ".rarPK" ascii
        $s2 = ".cmdPK" ascii
        $s3 = ".vbsPK" ascii
        $s4 = ".exePK" ascii

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and
        filesize > 1MB and filesize < 7MB and
        #rust > 10 and any of ($x*) and 3 of ($s*)
}