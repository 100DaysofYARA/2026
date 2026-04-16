rule ta_heraldwerewolf_telemos_backdoor_ps1
{
    meta:
        description = "Detects Herald Werewolf (Telemancon) Telemos (TMCShell) backdoor"
        author = "@t3ft3lb"
        date = "2026-01-26"
        reference = "https://www.f6.ru/blog/telemancon/"
        hash1 = "af00eab119b59e37fabafdaf427e505781f0c6d997b1643c9a36976954a61e90"
        hash2 = "1e6e10e8ec9eddcf1ad06bfd9aaaaaef6b8228affb2ca4e6d0b5fc14ebaa32c4"
        hash3 = "373361d3c3a12e436c44d7ed0374582968ad8a1883e1b69af82ad8effbb12ce0"

    strings:
        $s0 = ")\"|&$" ascii
        $s1 = "';foreach($" ascii
        $s2 = "])$($" ascii

    condition:
        uint8(0) == 0x24 and
        filesize > 2KB and filesize < 8KB and
        $s0 in (filesize - 25 .. filesize) and
        $s1 and #s2 in (@s1 .. filesize) > 4
}
