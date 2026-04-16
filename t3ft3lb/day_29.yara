rule ta_fairy_wolf_unicorn_hta_dropper
{
    meta:
        description = "Detects Fairy Wolf (Unicorn) HTA dropper delivering Unicorn stealer"
        author = "@t3ft3lb"
        date = "2026-01-29"
        reference = "https://securelist.ru/unicorn-data-stealing-scripts/110606/"
        hash1 = "0ef9cfd1a5dd6e64447a801b031aa963e0031dcf772c62faf5af88f643b594ad"
        hash2 = "b6e0c2af4398154ed528e370c5fe2435acdee9f75f3c8459df37436ef8f251af"
        hash3 = "13a72509684da6b6c8a6df555b534b6dae1f8c4c0466b134a144b9f78436d0c0"

    strings:
        $html = "<!DOCTYPE html>" ascii fullword

        $s0 = "HTA:APPLICATION" ascii fullword
        $s1 = "document.getElementById" ascii fullword
        $s2 = "M440-440H200v-80h240v-240h80v240h240v80H520v240h-80v-240Z" ascii fullword

        $r = /[0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12}/ ascii fullword

    condition:
        $html in (0 .. 20) and
        filesize > 50KB and filesize < 500KB and
        all of ($s*) and #r > 300
}