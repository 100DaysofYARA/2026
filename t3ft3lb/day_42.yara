rule ta_vortex_werewolf_stager_ps1
{
    meta:
        description = "Detects Vortex Werewolf (SkyCloak) PowerShell stager"
        author = "@t3ft3lb"
        date = "2026-02-11"
        reference_1 = "https://bi.zone/eng/expertise/blog/nadvigayushchiysya-tsiklon-vortex-werewolf-atakuet-rossiyu/"
        reference_2 = "https://www.seqrite.com/blog/operation-skycloak-tor-campaign-targets-military-of-russia-belarus/"
        reference_3 = "https://cyble.com/blog/weaponized-military-documents-deliver-backdoor/"
        hash1 = "ac5d15ef531aea04ae4af6ba43eccfec8adcb8f92809d4f5a90731871a7a411a"
        hash2 = "85fba8ba8377974392b9147a2adf2d2955e9dfbb8d9e0659c7f90487b1105ae7"
        hash3 = "0b9df542755298cd0b087681efbfaf91d35209966ff3bd8368ba65bcc0536a59"

    strings:
        $s0 = "Count -ge 10" ascii wide fullword
        $s1 = "Count -ge 50" ascii wide fullword
        $s2 = "New-Object System.Threading.Mutex" ascii wide fullword
        $s3 = "$env:USERDOMAIN+'\\'+$env:USERNAME" ascii wide fullword
        $s4 = "xml | Out-String ).Replace('$UserId'" ascii wide fullword
        $s5 = "Start-ScheduledTask" ascii wide fullword
        $s6 = "while (-not (Test-Path" ascii wide fullword
        $s7 = "Substring(0, 56)" ascii wide fullword
        $s8 = ".onion/lst?q=" ascii wide fullword
        $s9 = "curl --retry 1000 --retry-delay 3 --retry-all-errors -m 120 -s --socks5-hostname localhost:9050" ascii wide fullword

    condition:
        (uint32(filesize-4) == 0x007D007D or uint16(filesize-2) == 0x7D7D) and
        filesize > 1KB and filesize < 6KB and
        7 of them
}