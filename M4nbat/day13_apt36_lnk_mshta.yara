import "lnk"

rule APT36_LNK_MSHTA_Dropper {
    meta:
        author = "M4nbat"
        description = "Detects APT36 (Transparent Tribe) LNK files masquerading as PDFs that utilize mshta.exe for remote payload execution."
        date = "2026-01-31"
        yarahub_author_twitter = "@knappresearchlb"
        yarahub_reference_link = "https://www.cyfirma.com/research/apt36-multi-stage-lnk-malware-campaign-targeting-indian-government-entities/"
        yarahub_reference_md5 = "ceb715db684199958aa5e6c05dc5c7f0"
        yarahub_reference_sha256 = "6575196556b69352e6988753238c926c48970e28e19c0167c6999120638e8749"
        yarahub_uuid = "26a8f15b-9d41-4c17-9b88-59752b952f9c"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        malpedia_family = "win.transparent_tribe"

    strings:
        // PDF stream markers embedded in the LNK
        $pdf0 = "obj" ascii fullword
        $pdf1 = "endobj" ascii fullword
        $pdf2 = "stream" ascii fullword
        $pdf3 = "endstream" ascii fullword
        $pdf4 = "/Type /Catalog" ascii
        
        // Command line artifacts
        $mshta = "mshta" ascii nocase

    condition:
        // LNK File Header
        uint32(0) == 0x0000004C and
        // High confidence indicators of an embedded PDF inside the LNK
        3 of ($pdf*) and
        // Behavioral check via LNK module
        (
            lnk.cmd_line_args contains "mshta" or 
            lnk.cmd_line_args contains "http"
        ) and
        filesize > 50KB
}
