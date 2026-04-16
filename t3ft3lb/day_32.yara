import "lnk"

rule ta_horned_werewolf_initial_loader_lnk
{
    meta:
        description = "Detects Horned Werewolf (Mustang Panda) LNK initial loader"
        author = "@t3ft3lb"
        date = "2026-02-01"
        reference_1 = "https://strikeready.com/blog/cn-apt-targets-serbian-government/"
        reference_2 = "https://martinkubecka.sk/posts/2025-10-29-chinese_unc6384_malware_campaign_exploits_cambodia_thailand_crisis/"
        hash1 = "87929c8f53341a5e413950d33c7946c64e1d4b2eba6d1a8b2d08ef56f7065052"
        hash2 = "e31eafb49dbcad079ff177703b5a033f3e0365991cf28492339eccfe0fdf812c"
        hash3 = "8635dcc2001514febc6a07714b8cf6a3684b4c4c3b8fc0e08b2f6b92a045e3cc"

    condition:
        uint32(0) == 0x0000004C and uint32(4) == 0x00021401 and
        filesize > 1KB and filesize < 4KB and
        lnk.icon_location == ".\\WindowssSystem326Shell32.pdf" and
        lnk.cmd_line_args contains "-Re -Inc *'" and
        lnk.cmd_line_args contains "-1)]);" and
        lnk.cmd_line_args contains "TaR -xvf $Env:" and
        (
            lnk.cmd_line_args contains "[System.IO.File]::ReadAllBytes" or
            lnk.cmd_line_args contains "[System.IO.File]::OpenRead"
        )

}
