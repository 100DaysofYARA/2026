rule ta_rainbow_hyena_phantomcsloader_backdoor
{
    meta:
        description = "Detects Rainbow Hyena (Head Mare, PhantomCore) PhantomCSLoader backdoor"
        author = "@t3ft3lb"
        date = "2026-03-17"
        reference = "https://securelist.ru/head-mare-new-phantom-backdoors-and-ssh-tunneling/113473/"
        hash = "bcd75f825881aa61273b23d7ea370a89353327916483059f75339f7094382964"

    strings:
        $dotnet = ".NETFramework" ascii fullword

        $pdb = "C:\\Tools\\Git tools\\CUSTOM\\CSLoader\\Client\\CSLoader\\obj\\Release\\CSLoader.pdb" ascii fullword

        $s0 = "CSLoader" ascii fullword
        $s1 = "/register/" wide fullword
        $s2 = "/get_command/" wide fullword
        $s3 = "/result/" wide fullword
        $s4 = "/C whoami" wide fullword
        $s5 = "File downloaded successfully to " wide fullword
        $s6 = "Error downloading file: " wide fullword
        $s7 = "Error: Invalid load command format. Use: load <URL> <DESTINATION>" wide fullword

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and
        filesize > 4KB and filesize < 20KB and
        $dotnet and ($pdb or 6 of ($s*))
}