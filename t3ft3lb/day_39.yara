rule tool_ultravnc_config_ini
{
    meta:
        description = "Detects UltraVNC configuration INI file"
        author = "@t3ft3lb"
        date = "2026-02-08"
        reference = "https://uvnc.com/docs/ultravnc-server/69-ultravnc-ini.html"
        hash1 = "4ea68d0155f80e0ecade3cba47aa81c3b40399fd16b7116c0161151bf7e4b178" // Core Werewolf (Awaken Likho, GamaCopy)
        hash2 = "a2e0fe2d385dabcdfb024100216d259ddd1fa9907e982d297846fd29b8d4d415" // Disastrous Werewolf (Gamaredon Group)

    strings:
        $s0 = "[admin]" ascii fullword
        $s1 = "FileTransferEnabled" ascii fullword
        $s2 = "FTUserImpersonation" ascii fullword
        $s3 = "BlankMonitorEnabled" ascii fullword
        $s4 = "UseDSMPlugin" ascii fullword
        $s5 = "DSMPlugin" ascii fullword
        $s6 = "XDMCPConnect" ascii fullword
        $s7 = "HTTPPortNumber" ascii fullword
        $s8 = "LocalInputsDisabled" ascii fullword
        $s9 = "EnableJapInput" ascii fullword
        $s10 = "RemoveFontSmoothing" ascii fullword
        $s11 = "RemoveAero" ascii fullword
        $s12 = "Avilog" ascii fullword
        $s13 = "AllowEditClients" ascii fullword
        $s14 = "MSLogonRequired" ascii fullword
        $s15 = "NewMSLogon" ascii fullword
        $s16 = "ConnectPriority" ascii fullword
        $s17 = "[UltraVNC]" ascii fullword
        $s18 = "passwd" ascii fullword
  
    condition:
        uint32(0) == 0x7265505B and
        filesize > 400 and filesize < 1500 and
        12 of them
}