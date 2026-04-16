rule ta_silent_werewolf_xdigo
{
    meta:
        description = "Detects Silent Werewolf (XDSpy) XDigo malware"
        author = "@t3ft3lb"
        date = "2026-02-27"
        reference_1 = "https://harfanglab.io/insidethelab/sadfuture-xdspy-latest-evolution/"
        reference_2 = "https://securelist.ru/ataki-na-industrialnyj-i-gosudarstvennyj-sektory-rf/108229/"
        hash1 = "e32f04362ec4db90e024bfb57adf6e5c02f1061cd17dbf81a5bbc0b588119b25"
        hash2 = "0d983f5fb403b500ec48f13a951548d5a10572fde207cf3f976b9daefb660f7e"
        hash3 = "49714e2a0eb4d16882654fd60304e6fa8bfcf9dbd9cd272df4e003f68c865341"

    strings:
        $go = "Go build" ascii

        $x = "main.oooo" ascii fullword

        $s0 = "anti.go" ascii fullword
        $s1 = "crypto.go" ascii fullword
        $s2 = "file.go" ascii fullword
        $s3 = "main.go" ascii fullword
        $s4 = "net.go" ascii fullword
        $s5 = "log.go" ascii fullword
        $s6 = "settings.go" ascii fullword

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and
        filesize > 4MB and filesize < 12MB and
        $go and #x > 50 and 4 of ($s*)
}