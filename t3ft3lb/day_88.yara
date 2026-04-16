rule mlwr_blankgrabber_stealer
{
    meta:
        description = "Detects BlankGrabber stealer (PyInstaller variants)"
        author = "@t3ft3lb"
        date = "2026-03-29"
        reference_1 = "https://www.splunk.com/en_us/blog/security/blankgrabber-trojan-stealer-analysis-detection.html"
        reference_2 = "https://github.com/Blank-c/Blank-Grabber"
        hash1 = "268d12a71b7680e97a4223183a98b565cc73bbe2ab99dfe2140960cc6be0fc87"
        hash2 = "def254fa5a19b5407e834e83bb9511ef53630007b60563cad3f9f1008792188f"
        hash3 = "64a29cb00bf13a60bca026b1ba9e61ed6121c58b20a7459e04c346b07d9020e7"

    strings:
        $s0 = "pyinstaller" ascii fullword
        $s1 = "MEIPASS" ascii fullword
        $s2 = "pyaes" ascii fullword
        $s3 = "blank.aes" ascii
        $s4 = "rar.exe" ascii
        $s5 = "rarreg.key" ascii

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and
        filesize > 7MB and filesize < 15MB and
        all of them
}