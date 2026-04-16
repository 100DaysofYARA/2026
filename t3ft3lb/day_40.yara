import "lnk"

rule ta_vortex_werewolf_initial_loader_lnk
{
    meta:
        description = "Detects Vortex Werewolf (SkyCloak) LNK initial loader"
        author = "@t3ft3lb"
        date = "2026-02-09"
        reference_1 = "https://bi.zone/eng/expertise/blog/nadvigayushchiysya-tsiklon-vortex-werewolf-atakuet-rossiyu/"
        reference_2 = "https://www.seqrite.com/blog/operation-skycloak-tor-campaign-targets-military-of-russia-belarus/"
        reference_3 = "https://cyble.com/blog/weaponized-military-documents-deliver-backdoor/"
        hash1 = "a79b5162f9a49df3db4f001325938b9dc7bdc471b71108ed178350c89252e3a5"
        hash2 = "8f9029a5d5351078fc2f0b5499557c0f969b337817947314e37b2c7407ae2300"
        hash3 = "99ec6437f74eec19e33c1a0b4ac8826bcc44848f87cd1a1c2b379fae9df62de9"

    condition:
        uint32(0) == 0x0000004C and uint32(4) == 0x00021401 and
        filesize > 1KB and filesize < 4KB and
        lnk.icon_location contains "Microsoft\\Edge\\Application\\msedge.exe" and
        lnk.cmd_line_args contains ".zip';" and
        lnk.cmd_line_args contains "gc $env:APPDATA\\" and
        lnk.cmd_line_args contains "Start-Process -WindowStyle Hidden powershell" and
        (
            lnk.cmd_line_args contains "$env:USERPROFILE" or
            lnk.cmd_line_args contains "(where.exe /r $env:USERPROFILE"
        ) and
        (
            lnk.cmd_line_args contains "-DestinationPath $env:APPDATA" or
            lnk.cmd_line_args contains "-D $env:APPDATA"
        )
}
