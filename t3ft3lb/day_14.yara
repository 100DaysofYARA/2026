import "pe"

rule hunt_unsigned_pe_chinese_resources
{
    meta:
        description = "Detects unsigned PE files containing Chinese (zh-CN) resources"
        author = "@t3ft3lb"
        date = "2026-01-14"

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and
        not pe.is_signed and
        pe.number_of_sections > 2 and
        pe.number_of_resources <= 5 and
        (
            for any i in (0 .. (pe.number_of_resources - 1)):
            (
                pe.resources[i].language == 2052 // Chinese - People's Republic of China (zh-CN)
            )
        )
}