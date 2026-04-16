rule mlwr_crystalx_rat
{
    meta:
        description = "Detects CrystalX RAT"
        author = "@t3ft3lb"
        date = "2026-04-02"
        reference = "https://securelist.com/crystalx-rat-with-prankware-features/119283/"
        hash = "e08610b28e637679feaf243622adf3386a04bd24c915fe64c908d4d68b9fd203"

    strings:
        $go = "Go build" ascii

        $s0 = "runStealer" ascii fullword
        $s1 = "getStealerFileNames" ascii fullword
        $s2 = "stealScreenshot" ascii fullword
        $s3 = "stealUserInfo" ascii fullword
        $s4 = "stealDiscordTokens" ascii fullword
        $s5 = "stealSteamTokens" ascii fullword
        $s6 = "stealTelegram" ascii fullword
        $s7 = "stealYandex" ascii fullword
        $s8 = "stealOpera" ascii fullword
        $s9 = "stealBrowsers" ascii fullword
        $s10 = "getAutoStealMode" ascii fullword
        $s11 = "applyStealthMeasures" ascii fullword
        $s12 = "webInjectInstall" ascii fullword
        $s13 = "webInjectCDP" ascii fullword
        $s14 = "startMic" ascii fullword
        $s15 = "startWebcam" ascii fullword
        $s16 = "proxyStartPortFwd" ascii fullword
        $s17 = "startRemoteDesktop" ascii fullword

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and
        filesize > 7MB and filesize < 11MB and
        $go and 10 of ($s*)
}