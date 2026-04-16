rule Ransom_Crypto24_Note {
    meta:
        description = "Detects ransom notes from the Crypto24 Group ransomware operation."
        author = "M4nbat"
        date = "2026-01-11"
        threat_group = "Crypto24 Group"

    strings:
        // Unique header text
        $header = "Crypto24" ascii wide
          
        // Infrastructure markers
        $onion = "j5o5y2feotmhvr7cbcp2j2ewayv5mn5zenl3joqwx67gtfchhezjznad" ascii wide
        $session_id = "05e034eb421832ae9209e9c17441c93ee4509f2e6dae2b23595763e0a19fdcee52" ascii wide

        // Communications
        $session1 = "Contact Session ID:" ascii wide nocase
        $session2 = "Use the Session messenger"
        $session3 = "Device ID:"

        // Specific phrasing regarding recovery experts
        $warn1 = "DO NOT TRUST UNVERIFIED “RECOVERY EXPERTS”" ascii wide
        $warn2 = "They will then contact us pretending to be you" ascii wide
        $warn3 = "The device ID is an identifier that proves that you are a victim." ascii wide
        $warn4 = /We have exfiltrated over [0-9]+ ?(GB|TB) of your most sensitive business data/ ascii wide
          
    condition:
        $header and 
        ( 3 of ($warn*, $session*)) or ($onion or $session_id) ) and
        $claim and 
        filesize < 100KB
        //and (filename matches /README.*\.txt/i) or (filename matches /Decryption.*\.txt/i)
}
