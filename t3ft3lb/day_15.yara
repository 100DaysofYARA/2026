import "pe"

rule ta_translucent_werewolf_curlback_rat
{
    meta:
        description = "Detects Translucent Werewolf (APT36) CurlBack RAT"
        author = "@t3ft3lb"
        date = "2026-01-15"
        reference_1 = "https://www.seqrite.com/blog/goodbye-hta-hello-msi-new-ttps-and-clusters-of-an-apt-driven-by-multi-platform-attacks/"
        reference_2 = "https://www.cyfirma.com/research/apt36-lnk-based-malware-campaign-leveraging-msi-payload-delivery/"
        hash1 = "4df92d3c834aafd5e1ba3c7515a62b0bddd147c4b322401352dc63e46dca79c5"
        hash2 = "d0fe1419e415519a05666e39e25b1e69d744fd546367b93cf2065af3895d2850"
        hash3 = "d8acace07a595a1c9b07c4e341419580e06bdb6afcb58234eec3f6eb606dab58"

    strings:
        $curl = "curl/" ascii fullword

        $cmnd0 = "/dnammocmvitna" ascii fullword
        $cmnd1 = "/retsiger" ascii fullword
        $cmnd2 = "/taebtraeh" ascii fullword
        $cmnd3 = "/tluser_evicer" ascii fullword
        $cmnd4 = "/dnammoc_teg" ascii fullword
        $cmnd5 = "/sdnammoc" ascii fullword
        $cmnd6 = "/stluser" ascii fullword

        $mrsnn_twstr_cnst0 = { 65 89 07 6C }
        $mrsnn_twstr_cnst1 = { DF B0 08 99 }

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and
        filesize > 1MB and filesize < 3MB and
        pe.is_dll() and
        $curl and 4 of ($cmnd*) and all of ($mrsnn_twstr_cnst*)
}