rule Evolution_Ransomware_Note {
    meta:
        description = "Detects the ransom note associated with Evolution ransomware."
        author = "Manb4t"
        date = "2026-01-10"
        reference = "https://github.com/ThreatLabz/ransomware_notes/blob/main/evolution/README.%5Brand%5D.txt"

    strings:
        $s1 = "Your network has been accessed and has been placed in a restricted state." ascii wide nocase
        $s2 = "unauthorized authentication, lateral movement, and elevated access" ascii wide nocase
        $s3 = "Begin the communication process (www.tor.org):" ascii wide nocase
        $s4 = "No further modification of the data was performed" ascii wide nocase
        $s5 = "(on our servers)." ascii wide nocase
        $s6 = ".onion/chat/" ascii wide nocase
          
        $sig = "- Evolution" ascii wide fullword

    condition:
        ($sig and 2 of ($s*)) or (all of ($s*))
}
