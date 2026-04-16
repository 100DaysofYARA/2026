rule linux_trojanized_binary_kaiji : linux persistence Kaiji {
    meta:
        description = "This rule detects trojanized Linux binaries, specifically targeting those that resemble Kaiji malware. The combination of these strings suggests a malicious binary with persistence and potential crypto-mining capabilities."
        author = "zendanny"
        date = "2026-03-07"
        mitre_technique = "T1554"
        false_positive = "Legitimate binaries that contain related strings like 'mining' or 'miner' in their code, especially if they are related to cryptocurrency applications or development."

    strings:
        // directory the malware tends to copy itself to
        $copy_dir = "/etc/profile.d/" nocase
        
        // Crypto mining indicators (common in Perfctl)
        $crypto1 = "mining" nocase
        $crypto2 = "miner" nocase
        $crypto3 = "moneroocean" nocase
        $crypto4 = "xmrpool" nocase
        $crypto5 = "stratum" nocase
        
        // Commands Kaiji has been known to use
        $command1 = "netstat -anp" nocase
        $command2 = "lsof -i tcp" nocase
        $command3 = "ps auxf" nocase
        $command4 = "chmod 777" nocase

    condition:
        // ELF magic bytes
        uint32(0) == 0x464c457f and
        filesize > 50KB and filesize < 5MB and
        $copy_dir and
        // Plus crypto indicators
        any of ($crypto*) and
        any of ($command*)
}
