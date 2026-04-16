rule ta_iridescent_hyena_cmoon_rat
{
    meta:
        description = "Detects Iridescent Hyena (RGB-Team) CMoon RAT"
        author = "@t3ft3lb"
        date = "2026-04-06"
        reference_1 = "https://securelist.ru/how-the-cmoon-worm-collects-data/109988/"
        reference_2 = "https://securelist.ru/rgb-team/115109/"
        hash1 = "00ce60d07c498be48d48794767ef638c1eda96ebe05e1baaefff4043c859b092"
        hash2 = "a4be526be5359ad2981f439457fe652895731ad56c10c113c22a7836a9591e5d"

    strings:
        $dotnet = ".NETFramework" ascii fullword
        
        $s0 = "get_Servers" ascii fullword
        $s1 = "Utils.FileSearcher" ascii fullword
        $s2 = "Surveillance.Intelligence" ascii fullword
        $s3 = "Surveillance.NetDiscover" ascii fullword
        $s4 = "Surveillance.SmartGrabber" ascii fullword
        $s5 = "Surveillance.USBMonitor" ascii fullword
        $s6 = "Surveillance.BrowserStealer" ascii fullword
        $s7 = "Communication.C2Client" ascii fullword
        $s8 = "Communication.WIFIAccess" ascii fullword
        $s9 = "PerformFullScan" ascii fullword
        $s10 = "PrepareStealerPackets" ascii fullword
        $s11 = "PrepareSubmitNetDiscoverPackets" ascii fullword
        $s12 = "browserProfileRemotePath" ascii fullword

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and
        filesize > 250KB and filesize < 450KB and
        $dotnet and 7 of ($s*)
}