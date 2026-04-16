import "lnk"

rule ta_arcane_werewolf_malicious_lnk
{
    meta:
        description = "Detects Arcane Werewolf (Mythic Likho) malicious LNK files"
        author = "@t3ft3lb"
        date = "2026-01-04"
        reference = "https://bi.zone/eng/expertise/blog/arcane-werewolf-vernulsya-s-obnovlennym-implantom-loki/"
        hash1 = "e90f7f8594333e0a955a1daccbf5e9030ea86fa3c5c39f58b69d313304020fdd"
        hash2 = "5ce6b56442a9e85b1164886bfb71f49970cd856245058766d882fdb3fee6c372"

    condition:
        uint32(0) == 0x0000004C and uint32(4) == 0x00021401 and
        filesize > 1KB and filesize < 4KB and
        lnk.cmd_line_args contains "/v:on /c \"set" and
        lnk.cmd_line_args contains "powershell" and
        lnk.cmd_line_args contains "SilentlyContinue" and
        lnk.cmd_line_args contains "iwr -Uri $env" and
        lnk.cmd_line_args contains "conhost.exe"
}