rule hunt_T1036_007_zip_with_double_ext_lnk_file
{
    meta:
        description = "Detects ZIP archives containing LNK files with double extensions"
        author = "@t3ft3lb"
        date = "2026-01-19"
        reference = "https://attack.mitre.org/techniques/T1036/007/"
        hash1 = "af30d6c9431def22b93c52e7d7ba57a4290bbe6c94c7f822f0a5423c50671211" // Silent Werewolf (XDSpy)
        hash2 = "60a1dd1e63d5e11e34c70d3d40b8869e5964254e1b8caa4a64e5da9eb9d6aa15" // Gremlin Wolf (OldGremlin)
        hash3 = "2e4484d884b2d567a3ec0dba7d0851967f51bf1ef300ae39509744bb328349e9" // Fairy Wolf (Unicorn)

    strings:
        $lfh  = { 50 4B 03 04 }
        
        $double_ext = /\.(pdf|docx?|xlsx?|pptx?|jpg|jpeg|png)\.lnk/ ascii nocase

    condition:
        uint32(0) == 0x04034B50 and
        #lfh <= 5 and // number of files in ZIP
        $double_ext
}