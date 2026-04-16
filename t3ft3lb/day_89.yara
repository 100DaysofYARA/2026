rule mlwr_crysomerat_client
{
    meta:
        description = "Detects Crysome RAT client"
        author = "@t3ft3lb"
        date = "2026-03-30"
        reference = "https://www.cyfirma.com/research/crysome-rat-an-advanced-persistent-net-remote-access-trojan/"
        hash = "f30f32937999abe4fa6e90234773e0528a4b2bd1d6de5323d59ac96cdb58f25d"

    strings:
        $dotnet = ".NETFramework" ascii fullword

        $pdb = "Crysome.Client.pdb" ascii fullword

        $s0 = "AVKiller" ascii fullword
        $s1 = "IsCamMicPacket" ascii fullword
        $s2 = "InstallResetSurvival" ascii fullword
        $s3 = "ParentSpoof" ascii fullword
        $s4 = "--watcher" wide fullword
        $s5 = "--spoofed" wide fullword
        $s6 = "HH:mm:ss.fff" wide fullword
          
        $x0 = "Crysome" wide fullword
        $x1 = "CrysomeClient.InstanceMutex" wide fullword
        $x2 = "Crysome_debug.log" wide fullword
        $x3 = "/create /tn \"CrysomeLoader\" /tr \"" wide fullword
        $x4 = "CrysomeBackup" wide fullword
        $x5 = "CrysomeHvncDesktop" wide fullword
        $x6 = "Crysome.Client" wide fullword

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and
        filesize > 300KB and filesize < 700KB and
        $dotnet and ($pdb or 4 of ($s*) or 2 of ($x*))
}