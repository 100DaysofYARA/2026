rule ta_hoody_hyena_serpent
{
    meta:
        description = "Detects Hoody Hyena (BO Team) Serpent tunneling hacktool"
        author = "@t3ft3lb"
        date = "2026-03-05"
        reference = "https://t.me/four_rays/99"
        hash = "c95a39a992d85d7c7299a84780f3418bc1574c9adcd6318b5c3116405f48269f"

    strings:
        $go = "Go build" ascii

        $x = "vegas/serpent" ascii fullword

        $s0 = "cmd/main/master.go" ascii fullword
        $s1 = "cmd/main/relay.go" ascii fullword
        $s2 = "pkg/common/polyfills.go" ascii fullword
        $s3 = "pkg/socks5/relay.go" ascii fullword
        $s4 = "pkg/fastmsg/message.go" ascii fullword
        $s5 = "pkg/treenet/treenet.go" ascii fullword

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and
        filesize > 1MB and filesize < 10MB and
        $go and (#x > 20 or 5 of ($s*))
}