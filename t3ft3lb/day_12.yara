rule ta_cloud_werewolf_powershower_obf_ps1
{
    meta:
        description = "Detects Cloud Werewolf (Cloud Atlas) obfuscated PowerShower samples"
        author = "@t3ft3lb"
        date = "2026-01-12"
        reference_1 = "https://attack.mitre.org/software/S0441/"
        reference_2 = "https://securelist.com/cloud-atlas-attacks-with-new-backdoor-vbcloud/115103/"
        hash1 = "d4bf580c363a2b9501c2a7fb10a1fedd917c568bcc689e8b20cfc3a86880a3e4"
        hash2 = "aefb88c0814c3f9f57948b228fb1d45bd7116c250299c4beb056ea34bb8e349a"
        hash3 = "9a18f55d8ac46efae9915bffc784567c60bcc706e77d60638090e0c9a6d38649"

    strings:
        $x0 = "{1}{2}{3}{4}{5}{6}{7}{8}{9}{10}" ascii fullword
        $x1 = "{000}{001}{002}{003}{004}{005}{006}{007}{008}{009}{0010}" ascii fullword
        $x2 = /\$[A-Z]{6}=\$[A-Z]{7}/ ascii fullword
        $x3 = { 67 42 31 41 ?? 34 41 59 77 42 30 41 [4] 77 42 75 41 43 41 41 }

        $s = "[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String(" ascii fullword
    
    condition:
        filesize > 1KB and filesize < 25KB and
        any of ($x*) and $s in (filesize-250..filesize)
}