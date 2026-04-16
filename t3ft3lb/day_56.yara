rule cve_2026_21509_rtf
{
    meta:
        description = "Detects RTF files with CVE-2026-21509"
        author = "@t3ft3lb"
        date = "2026-02-25"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-21509"
        hash1 = "2bbcbc88d04615079fa17708c62f07ccb138c19bb9ed78ae43f9172cd91931ba"
        hash2 = "c91183175ce77360006f964841eb4048cf37cb82103f2573e262927be4c7607f"
        hash3 = "d944abab1481457eacf9f1d08f835980c2146ec91513e2eb94714c6abaec5f34"

    strings:
        $objdata = "\\objdata" ascii fullword

        $clsid_s = "objclass Shell.Explorer.1" ascii fullword
        
        // CLSID = "{EAB22AC3-30C1-11CF-A7EB-0000C05BAE0B}" (Shell.Explorer.1)
        $clsid_h = { 43 [0-20] 33 [0-20] 32 [0-20] 41 [0-20] 42 [0-20] 32 [0-20] 45 [0-20] 41 [0-20]
                     43 [0-20] 31 [0-20] 33 [0-20] 30 [0-20] 43 [0-20] 46 [0-20] 31 [0-20] 31 }
        
    condition:
        uint32(0) == 0x74725C7B and
        (
            $clsid_s in (@objdata - 100 .. @objdata) or
            $clsid_h in (@objdata .. @objdata + 60000)
        )
}