rule linux_trojanized_cron_binary : linux persistence perfctl cron {
    meta:
        description     = "Detects trojanized cron binaries that hide malicious cron jobs, with indicators resembling Perfctl"
        author          = "zendanny"
        date            = "2026-03-07"
        mitre_technique = "T1554"
        reference = "https://ostechnix.com/cron-persistence-linux-malware/"
        
    strings:
        // Standard cron binary strings that should be present
        $cron1 = "crontab" nocase
        $cron2 = "/var/spool/cron" nocase
        $cron3 = "/etc/crontab" nocase
        
        // Crypto mining indicators (common in Perfctl)
        $crypto1 = "mining" nocase
        $crypto2 = "miner" nocase
        $crypto3 = "xmrig" nocase
        $crypto4 = "stratum" nocase
        
        // File filtering/hiding logic
        $hide1 = "filter" nocase
        $hide2 = "strcmp" nocase
        $hide3 = "strstr" nocase

    condition:
        // ELF magic bytes
        uint32(0) == 0x464c457f and
        filesize > 50KB and filesize < 5MB and
        // Must contain basic cron functionality
        any of ($cron*) and
        // Plus suspicious additions not found in legitimate cron
        (any of ($crypto*)) and
        // Contains string manipulation (for hiding cron jobs)
        any of ($hide*)
}
