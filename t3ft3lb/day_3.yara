rule ta_bloody_wolf_malicious_pdf
{
    meta:
        description = "Detects Bloody Wolf malicious PDF files"
        author = "@t3ft3lb"
        date = "2026-01-03"
        reference_1 = "https://bi.zone/eng/expertise/blog/evolyutsiya-bloody-wolf-novye-tseli-novye-sredstva-ataki/"
        reference_2 = "https://www.group-ib.com/blog/bloody-wolf/"
        hash1 = "7480a0b62f7e0b97f2ec2059b036b62d84deb8ea4a14388d88407195e511b8d4" // 2025
        hash2 = "6ae1367a79002f84ebd2ee6aac4dbaaaa3d8725dd40d82a3e3100124b6b9519f" // 2024
        hash3 = "c243b17fe0471ef8216db433783246ce10ca14ff9c4eb4603d5b7aa1e05899d3" // 2023

    strings:
        $s0 = "%%EOF" ascii fullword
        $s1 = "/S /URI\x0A/URI (https" ascii fullword
        $s2 = "java" ascii

    condition:
        uint32(0) == 0x46445025 and $s0 in (filesize-10..filesize) and
        filesize > 40KB and filesize < 2MB and
        #s1 > 1 and $s2
}