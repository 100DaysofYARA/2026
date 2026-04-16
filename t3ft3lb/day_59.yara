rule ta_prosperous_werewolf_trinper_backdoor
{
    meta:
        description = "Detects Prosperous Werewolf (Team46, TaxOff, ForumTroll) Trinper (LeetAgent) backdoor"
        author = "@t3ft3lb"
        date = "2026-02-28"
        reference_1 = "https://vms.drweb.com/virus/?lng=en&i=28913281"
        reference_2 = "https://global.ptsecurity.com/en/research/pt-esc-threat-intelligence/taxoff-um-you-ve-got-a-backdoor/"
        reference_3 = "https://securelist.com/forumtroll-apt-hacking-team-dante-spyware/117851/"
        hash1 = "2a0c6a66774cc535f51e1a12d81ba6aa346934aa542291cee0c57f3bc9373a8e"
        hash2 = "7e82b3f1be69d34684a4aa4823ef0d5ae864db3501fae5a0c3697bcd28df5cef"
        hash3 = "e93c1a0696b59a58e2444eb69ddf165eed71ad159624674a7fe6c91e9852443a"

    strings:
        $s0 = "%02d.%02d.%04d %02d:%02d:%02d" wide fullword
        $s1 = "cmd.exe /u /c \"%s\"" wide fullword
        $s2 = "[ESC]" wide fullword
        $s3 = "[BS]" wide fullword
        $s4 = "POST" wide fullword
        $s5 = "ChainingModeCBC" wide fullword
        $s6 = "docx\x00\x00\x00\x00xlsx\x00\x00\x00\x00pptx" wide fullword
        $s7 = "Mozilla/5.0\x00/x86\x00\x00\x00\x00/x64\x00\x00\x00\x00/in" wide fullword

        $f0 = "BCryptEncrypt" ascii fullword
        $f1 = "PeekNamedPipe" ascii fullword
        $f2 = "WriteProcessMemory" ascii fullword
        $f3 = "HttpOpenRequestW" ascii fullword
        $f4 = "FindNextFile" ascii
        $f5 = "GetDriveType" ascii

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and
        filesize > 150KB and filesize < 500KB and
        6 of ($s*) and 5 of ($f*)
}