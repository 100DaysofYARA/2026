import "pe"

rule ta_rare_werewolf_downloader_cpp
{
    meta:
        description = "Detects Rare Werewolf (Librarian Likho (ex Ghouls), Rezet) C++ downloader"
        author = "@t3ft3lb"
        date = "2026-02-16"
        reference = "https://www.kaspersky.ru/blog/librarian-likho-new-tools/40695/"
        hash1 = "aab6d8c7e1db0441c487e81bf4246791e73d34f2848e9ea24f282f29f77b719c"
        hash2 = "d997aa0f0c5388be5a00a9f5d17fe59d11d33b2d3bdde8c73c71cb1831924efa"
        hash3 = "4b78beeed7e2d3cefeb9bd2a996625840b515425fad0fbc5a552169245753189"

    strings:
        $s0 = "limpis2903392" wide fullword
        $s1 = "Updater" wide fullword
        $s2 = "open" wide fullword
        $s3 = "runas" wide fullword
        $s4 = "r\x00w\x00a\x00rb\x00\x00wb\x00\x00ab\x00\x00r+\x00\x00w+\x00\x00a+" wide fullword
        $s5 = "r+b\x00w+b\x00a+b\x00wx\x00\x00w+x\x00wbx\x00w+bx" wide fullword

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and
        filesize > 100KB and filesize < 1MB and 
        (
            (
                5 of ($s*) and
                pe.imports("KERNEL32.dll", "GetTempPathW") and
                pe.imports("KERNEL32.dll", "FindResourceW") and
                pe.imports("KERNEL32.dll", "LoadResource") and
                pe.imports("KERNEL32.dll", "SizeofResource") and
                pe.imports("KERNEL32.dll", "LockResource") and
                pe.imports("SHELL32.dll", "ShellExecuteExW") and
                pe.imports("WININET.dll", "InternetOpenW") and
                pe.imports("WININET.dll", "InternetOpenUrlA") and
                pe.imports("WININET.dll", "InternetReadFile") and
                pe.imports("WININET.dll", "InternetCloseHandle")
            ) or
            pe.imphash() == "9fa64c4e91664537145f750be9554a86" or
            pe.imphash() == "604375ce0b5745a4756d514eb85801a4"
        )
}