rule phish_apt28_strings {  
    meta:
        author = "manb4t"
        desc = "phishing email rule focussing on powershell and DDE"
    strings:
        $header = "[Content_Types].xml<?xml version"
        $s1 = "(New-Object System.Net.WebClient).DownloadString"
        $s2 = "powershell -enc $e # \" \"a slow internet connection\" \"try again later\""
        $s3 = "MSWord.exe\\\\..\\\\..\\\\..\\\\..\\\\"
        $s4 = "\\\\..\\\\..\\\\..\\\\Windows\\\\System32"
        $d1 = "2017-10-27T22:23:00Z"
        $d2 = "2017-10-27T22:25:00Z"
    condition:
        $header in (0..50) and //anchor using 0..50 bytes to prevent it matching on something that is not an email e.g. a blog or document talking about the intrusion or phish
        3 of ($s*) and
        1 of ($d*)
}
