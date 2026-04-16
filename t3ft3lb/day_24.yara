rule susp_ta_silent_werewolf_arj_with_rar_and_com
{
    meta:
        description = "Detects Silent Werewolf (XDSpy) ARJ archives with .rar and .com files"
        author = "@t3ft3lb"
        date = "2026-01-24"
        reference_1 = "https://securelist.ru/ataki-na-industrialnyj-i-gosudarstvennyj-sektory-rf/108229/"
        reference_2 = "https://harfanglab.io/insidethelab/sadfuture-xdspy-latest-evolution/"
        hash1 = "d367dda5bb5d5466020e2d32386f3b9643851f1a10fbf5da22fe634db2230692"
        hash2 = "ef34c433c818774b466ba4e6f677b1c6cf51bb9213a60fd779fd7df39011e97b"
        hash3 = "ffc538f2c6e91f07be067311ed143d28c5437a8af69974f751c043e2944d60b2"

    strings:
        $arj = { 60 EA ?? 00 22 0B 01 0B 10 00 }
        $rar = ".rar" ascii
        $com = ".com" ascii

    condition:
        $arj at 0 and
        filesize > 50KB and filesize < 1MB and
        #rar == 1 and $rar in (38 .. 100) and
        #com == 1 and $com in (@rar .. @rar + 100)
}