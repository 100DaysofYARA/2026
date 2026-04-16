rule ta_hoody_hyena_zeronetkit_backdoor
{
    meta:
        description = "Detects Hoody Hyena (BO Team) ZeronetKit backdoor"
        author = "@t3ft3lb"
        date = "2026-02-05"
        reference = "https://securelist.ru/bo-team-upgrades-brockendoor-and-zeronetkit-backdoors/113536/"
        hash1 = "10d0114dba15bf9b19b7ef5f03fbbeae236daa78ceae7a362d12c66cb708d4a5" // PE32+
        hash2 = "a41e7083e6c53c02dc2e92dcfd830f32c4da5cca77cff11b0d258836b8216a40" // PE32+
        hash3 = "aeef89818b2212a0b7154eaad28183120ae2a7b90a553b5f4354cd1d7a010598" // ELF64

    strings:
        $go = "Go buildinf" ascii fullword

        $s0 = "wss://%s/ws" ascii
        $s1 = "malformed ws or wss URL" ascii
        $s2 = "zeronet" ascii fullword
        $s3 = "./dummy.go" ascii fullword
        $s4 = "./stage2.go" ascii fullword
        $s5 = "github.com/hashicorp/yamux" ascii fullword
        $s6 = "github.com/gorilla/websocket" ascii fullword
        $s7 = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11" ascii fullword
        $s8 = "master secret\x00\x00\x00key expansion" ascii fullword

    condition:
        (
         (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) or 
         (uint32(0) == 0x464C457F)
        ) and
        filesize > 3MB and filesize < 6MB and
        $go and 6 of ($s*)

}
