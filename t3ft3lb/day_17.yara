rule ta_eucalyptus_wolf_lazystealer
{
    meta:
        description = "Detects Eucalyptus Wolf (Lazy Koala) LazyStealer"
        author = "@t3ft3lb"
        date = "2026-01-17"
        reference = "https://global.ptsecurity.com/en/research/pt-esc-threat-intelligence/lazystealer-sophisticated-does-not-mean-better/"
        hash1 = "1db3d0ac68515b5c9876634605ba8492ba558f7df435bff2b20a74239107f3ec"
        hash2 = "e419a8158c6fe326dc7ab16dbd5f3b2723dffe8c9561fe835bb16f62a8fa61f5"
        hash3 = "b93b4e42a6325d4656b5ac1e3dddadddb29c6e903a45442773e76591f7741a71"

    strings:
        $p0 = "_MEI%d" fullword wide
        $p1 = "PyInstaller" ascii fullword

        $s0 = "b_bz2.pyd" ascii fullword
        $s1 = "b_ctypes.pyd" ascii fullword
        $s2 = "b_decimal.pyd" ascii fullword
        $s3 = "b_hashlib.pyd" ascii fullword
        $s4 = "b_lzma.pyd" ascii fullword
        $s5 = "b_queue.pyd" ascii fullword
        $s6 = "b_socket.pyd" ascii fullword
        $s7 = "b_sqlite3.pyd" ascii fullword
        $s8 = "b_ssl.pyd" ascii fullword
        $s9 = "b_wmi.pyd" ascii fullword
        $s10 = "bselect.pyd" ascii fullword
        $s11 = "bunicodedata.pyd" ascii fullword
        $s12 = "bwin32\\win32crypt.pyd" ascii fullword

        $x0 = "bhello.cp39-win_amd64.pyd" ascii fullword
        $x1 = "bpdfbyte.cp39-win_amd64.pyd" ascii fullword
        $x2 = "bdocpdf.cp39-win_amd64.pyd" ascii fullword
        $x3 = "bCapybaraPDF.cp39-win_amd64.pyd" ascii fullword
        $x4 = "bcharset_normalizer\\md.cp312-win_amd64.pyd" ascii fullword

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and
        filesize > 7MB and filesize < 11MB and
        all of ($p*) and 11 of ($s*) and any of ($x*)
}