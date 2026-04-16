rule ta_prosperous_werewolf_lnk_downloader
{
    meta:
        description = "Detects Prosperous Werewolf (Team46, TaxOff, ForumTroll) LNK downloader"
        author = "@t3ft3lb"
        date = "2026-03-24"
        reference_1 = "https://news.drweb.com/show/?i=14899&lng=en"
        reference_2 = "https://habr.com/ru/companies/pt/articles/841176/"
        hash1 = "96dccf3f6b5288a5f5a6d6534b3bf9188aaaa85eb637510a972cf992063e66f7"
        hash2 = "2cc62e6bdc66384585f03883f21087f4e8b315a749e31818781bd1169658babf"
        hash3 = "c5872027ce3ed22bcc5c497f9b13542243ae400489fc0ebd4d10c64c7739ec1e"
    
    strings:
        $s0 = "powershell.exe" ascii fullword
        $s1 = "-ep Bypass -nop -c \"irm https:" wide fullword

        $r = /\?id=[a-z0-9]{32}\s*\|\s*iex/i wide

    condition:
        uint32(0) == 0x0000004C and uint32(4) == 0x00021401 and
        filesize > 400 and filesize < 4KB and
        $s0 and $r in (@s1 .. @s1 + 150)
}