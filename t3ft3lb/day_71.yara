rule ta_forgery_werewolf_lazyoneloader
{
    meta:
        description = "Detects Forgery Werewolf (FakeTicketer) LazyOneLoader"
        author = "@t3ft3lb"
        date = "2026-03-12"
        reference_1 = "https://www.seqrite.com/blog/operation-hollowquill-russian-rd-networks-malware-pdf/"
        reference_2 = "https://habr.com/ru/companies/F6/news/897066/"
        hash = "fdf0ea5d761352791545b1af0223853b31592996600c4ee5f1122e546c6165d3"

    strings:
        $go = "Go build" ascii

        $s0 = "syscall.LazyProc" ascii fullword
        $s1 = "syscall.LazyDLL" ascii fullword
        $s2 = "goinj/main.go" ascii fullword
        $s3 = "path\tmyapp\nmod\tmyapp" ascii fullword
        $s4 = "shellcode.txt" ascii
        $s5 = "c:\\Users\\Public\\OneDrive.exe" ascii
        
        $h0 = { 48 C1 FA 1C 48 89 C8 48 C1 F9 3F 48 29 CA 48 69 CA 00 CA 9A 3B }
        $h1 = { 4C C7 84 24 [4] 77 64 49 57 48 BA 6C 50 63 6C 5A 50 72 51 }

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and
        filesize > 1MB and filesize < 4MB and 
        $go and 5 of ($s*) and any of ($h*)
}