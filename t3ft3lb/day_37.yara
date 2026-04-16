rule cve_2025_6218_winrar
{
    meta:
        description = "Detects RAR archives with CVE-2025-6218"
        author = "@t3ft3lb"
        date = "2026-02-06"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-6218"
        hash1 = "fe2587dd8d9755b7b3a106b6e46519a1ce0a8191eb20821d2f957326dbf912e9" // Paper Werewolf (GOFFEE)

    strings:
        $s0 = " //.. //.. /" ascii fullword
        $s1 = " /.. /.. /" ascii fullword

        $x = "\x03STM" ascii

    condition:
        uint32(0) == 0x21726152 and
        (#s0 > 1 or #s1 > 3) and not $x
}
