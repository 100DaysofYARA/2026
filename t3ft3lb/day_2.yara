rule cve_2025_8088_winrar
{
    meta:
        description = "Detects RAR archives with CVE-2025-8088"
        author = "@t3ft3lb"
        date = "2026-01-02"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-8088"
        hash1 = "282b50b7e3b2e96635719eb173a809d526329dccf189e349bf2b28f5d9d6ea94" // Paper Werewolf (GOFFEE)
        hash2 = "107f3d1fe28b67397d21a6acca5b6b35def1aeb62a67bc10109bd73d567f9806" // RomCom
        hash3 = "133e080d5e48701c9ab880f98c5defcba739a833ea6e7ba30aed33f5014f4229" // unk_ta (payload: XWorm)

    strings:
        $s0 = "\x03STM" ascii
        $s1 = "\\\\..\\\\" ascii fullword
        $s2 = "\\..\\..\\" ascii fullword

    condition:
        uint32(0) == 0x21726152 and
        $s0 and (#s1 > 2 or #s2 > 2)
}
