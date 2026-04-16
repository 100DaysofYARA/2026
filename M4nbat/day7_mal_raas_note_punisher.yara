rule ransom_note_punisher_ransomware {
   
   meta:

      description = "Rule to detect the ransom note delivered by Kraken Cryptor Ransomware"
      author = "M4nbat"
      date = "2026-01-06"
      rule_version = "v1"
      malware_type = "ransomware"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      reference = "https://github.com/ThreatLabz/ransomware_notes/tree/main/punisher"

   strings:

      $s1 = "--= System Security Notice =--" fullword ascii
      $s2 = "Your system has been secured with advanced encryption technology." fullword ascii
      $s3 = "All your files including personal data, financial reports, and important documents have been protected using military-grade encryption." fullword ascii
      $s4 = "To restore access to your files and continue your business operations, you will need to obtain the decryption key." fullword ascii
      $s5 = "This is a standard security measure to ensure data integrity and prevent unauthorized access." fullword ascii
      $s6 = "We strongly advise against attempting to use third-party decryption tools, as this may result in permanent data loss." fullword ascii
      $s7 = "Our encryption system is designed to be secure and cannot be bypassed by external tools." fullword ascii
      $s8 = "1 - Download Tor browser from: https://www.torproject.org/download/" fullword ascii
      $s9 = "2 - Visit one of our secure communication channels:" fullword ascii
      $s10 = "3 - Use your unique ticket ID for authentication:" fullword ascii
      $tor = ".onion"
      //torfull = "$http://jh3zjsqgqk5woyuls7dxgdtorcycjx3i3sgdqpwdbiizunb5vbmppiid.onion"

   condition:

      uint16(0) == 0x4120 and
      filesize < 9KB and
      all of ($s*) and
      $tor
}

