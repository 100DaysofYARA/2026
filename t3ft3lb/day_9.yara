rule T1036_008_polyglot_pe_zip
{
    meta:
        description = "Detects PE+ZIP polyglot files (T1036.008)"
        author = "@t3ft3lb"
        date = "2026-01-09"
        reference_1 = "https://attack.mitre.org/techniques/T1036/008/"
        reference_2 = "https://bi.zone/eng/expertise/blog/rainbow-hyena-snova-atakuet-novyy-bekdor-i-smena-taktik/"
        reference_3 = "https://www.kaspersky.co.uk/blog/polyglot-malware-masking-technique/28847/"
        hash1 = "c190435790d365d8884645e76e5fe1ec21e4042ff65c65aae714527fb9111fcd" // Rainbow Hyena (Head Mare): PhantomPyramid
        hash2 = "01f12bb3f4359fae1138a194237914f4fcdbf9e472804e428a765ad820f399be" // Rainbow Hyena (Head Mare): PhantomRemote (EAGLET)
        hash3 = "c34fb316e7b60cff25be9c86e5736b802b9e99b1ac29daa03b08c3435b6ada8c" // Rainbow Hyena (Head Mare): PhantomDL/PhantomRAT

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and
        uint32(filesize-26) == 0x00000000 and uint32(filesize-22) == 0x06054B50
}