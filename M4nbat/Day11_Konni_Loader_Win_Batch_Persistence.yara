rule Loader_Win_Batch_Persistence_Resilient {
    meta:
        author = "M4nbat"
        description = "Detects batch loaders using granular PowerShell XOR-decryption and schtasks persistence."
        date = "2026-01-25"
        yarahub_author_twitter = "@knappresearchlb"
        yarahub_reference_link = "https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/"
        yarahub_reference_sha256 = "c3c8d6ea686ad87ca2c6fcb5d76da582078779ed77c7544b4095ecd7616ba39d"
        yarahub_uuid = "f47b9e5c-3a8b-4c9d-a123-9d572e0f6834"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        malpedia_family = "win.generic_loader"

    strings:
        /* PowerShell Components - Broken down for resilience */
        $ps_read = "[IO.File]::ReadAllBytes" ascii nocase
        $ps_enc  = "[Text.Encoding]::UTF8.GetBytes" ascii nocase
        $ps_loop = "for($i=0;$i -lt" ascii nocase
        $ps_xor  = "-bxor" ascii nocase
        $ps_conv = "[Text.Encoding]::UTF8.GetString" ascii nocase
        $ps_iex  = "iex $c" ascii nocase

        /* Persistence and Environmental Indicators */
        $sch_task = "schtasks /create" ascii nocase
        $sch_name = "OneDrive Startup Task" ascii wide
        $dir_prog = "C:\\ProgramData\\" ascii nocase
        $self_del = "del \"%~f0\"" ascii nocase

    condition:
        (uint16(0) == 0x6540 or uint16(0) == 0x4540) // Detects '@e' or '@E' (common in @echo off)
        and (
            4 of ($ps_*) or 
            (2 of ($ps_*) and 2 of ($sch_*, $dir_prog, $self_del))
        )
}
