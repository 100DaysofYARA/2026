rule T1221_doc_1table_template_injection
{
    meta:
        description = "Detects document template injection via the 1Table stream (T1221)"
        author = "@t3ft3lb"
        date = "2026-01-05"
        reference_1 = "https://attack.mitre.org/techniques/T1221/"
        reference_2 = "https://global.ptsecurity.com/en/research/pt-esc-threat-intelligence/apt-cloud-atlas-unbroken-threat/"
        reference_3 = "https://cert.by/?p=2631&lang=en"
        hash1 = "5c14458cc239fdcc937f62f249a7426a4ad073c1acc39bffdf11cf8f50c364c3" // Cloud Werewolf (Cloud Atlas)
        hash2 = "740aa02b0db085cd9ab2cf7b61361477a8ea1c9ee0a0e4b6c2726a26d37c5873" // Disastrous Werewolf (Gamaredon Group)

    strings:
        $ole_magic = { D0 CF 11 E0 A1 B1 1A E1 }
        $ole_1table_stream = "1Table" wide fullword
        $hex_http_wide = { 00 FF FF 12 00 00 00 00 00 ?? 00 (48 | 68) 00 (54 | 74) 00 (54 | 74) 00 (50 | 70) 00 }

    condition:
        $ole_magic at 0 and
        filesize < 10MB and
        $ole_1table_stream and $hex_http_wide
}