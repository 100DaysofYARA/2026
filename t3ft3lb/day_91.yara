rule ta_paper_werewolf_xll_loader
{
    meta:
        description = "Detects Paper Werewolf (GOFFEE) XLL loader"
        author = "@t3ft3lb"
        date = "2026-04-01"
        reference = "https://intezer.com/blog/tracing-a-paper-werewolf-campaign-through-ai-generated-decoys-and-excel-xlls/"
        hash1 = "0506a6fcee0d4bf731f1825484582180978995a8f9b84fc59b6e631f720915da"
        hash2 = "dbb3105384f52f89d2aefd75a24de4a11679e671c829490400f7f028e724a471"
        hash3 = "a49e7a76557a049f7625a58fa0328c393f6b0bc8ab0804238882bbabeee00c0b"

    strings:
        $f = "xlAutoOpen" ascii fullword
        
        $s0 = "APPDATA" ascii fullword
        $s1 = "LOCALAPPDATA" ascii fullword
        $s2 = "\x00%s%s\x00" ascii
        $s3 = "cmd.exe /C %s" ascii xor

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and
        filesize > 100KB and filesize < 2MB and
        $f and 3 of ($s*)
}