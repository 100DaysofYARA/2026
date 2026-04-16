rule ta_moonlight_hyena_zipwhisper_stealer_ps1
{
    meta:
        description = "Detects Moonlight Hyena (Punishing Owl) PowerShell stealer ZipWhisper"
        author = "@t3ft3lb"
        date = "2026-02-20"
        reference = "https://habr.com/ru/companies/pt/articles/990374/"
        hash1 = "09636fbca343f268ee7c0c033e37a9b007fe40ce914c4273ed961d84b52bed17"
        hash2 = "b1782f8f3440ce4b184f27c4047439aa998058ec17319a5b08031eda545d5a50"

    strings:
        $s0 = "Add-Type -AssemblyName System.IO.Compression.FileSystem" ascii fullword
        $s1 = "Add-Type -AssemblyName System.Windows.Forms" ascii fullword
        $s2 = "0x0050,0x0044,0x0046,0x0020,0x0444,0x0430,0x0439,0x043B,0x0020,0x043F,0x043E,0x0432,0x0440,0x0435,0x0436,0x0434,0x0451,0x043D,0x002E" ascii fullword
        $s3 = "0x041E,0x0448,0x0438,0x0431,0x043A,0x0430" ascii fullword
        $s4 = "$EscComputer/$EscUser" ascii fullword
        $s5 = "Parameter(Mandatory=$true)" ascii fullword
        $s6 = "[System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile" ascii fullword
        $s7 = "{0}-home-part{1}.zip" ascii fullword

        $x0 = "Get-ZipEntryPath" ascii fullword
        $x1 = "Write-ZipChunk" ascii fullword
        $x2 = "Upload-Zip" ascii fullword
        
    condition:
        filesize > 2KB and filesize < 7KB and
        4 of ($s*) and any of ($x*)
}