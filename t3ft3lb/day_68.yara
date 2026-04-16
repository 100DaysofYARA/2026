rule ta_core_werewolf_go_dropper
{
    meta:
        description = "Detects Core Werewolf (PseudoGamaredon, Awaken Likho) dropper written in Go"
        author = "@t3ft3lb"
        date = "2026-03-09"
        reference = "https://habr.com/ru/companies/F6/articles/808143/"
        hash1 = "fbd4a8052a69221f27467904f83b6c36fadf0d77043ac9d0e35b2be2e43ea3a2"
        hash2 = "e111527ae3ba900e98fddd61d4be45c24c559d2f6bc9b2ccd327c250d460d11b"
        hash3 = "bc96b7ee0ec9b01d6ec7b887ca8da6f452fbcc9203d6ab0a8f8ccfe4fe91900f"

    strings:
        $go = "Go build" ascii

        $x = "/home/kali/Desktop/000_BUILDER/main/main.go" ascii fullword

        $s0 = ".crdownloadPK" ascii
        $s1 = ".cmdPK" ascii
        $s2 = ".pdfPK" ascii
        $s3 = ".iniPK" ascii
        $s4 = "tmp.file." ascii
        $s5 = "VncViewer.class" ascii

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and
        filesize > 1MB and filesize < 5MB and
        $go and ($x or 4 of ($s*))
}