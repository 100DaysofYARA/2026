import "pe"

rule CrazyHunters_Ransomware
{
    meta:
        desc = "Detects Crazyhunters Ransomware"
        author = "@josh_penny"
        hash = "f72c03d37db77e8c6959b293ce81d009bf1c85f7d3bdaa4f873d3241833c146b"
        date = "2026-01-15"
    strings:
        $Prince = "Prince-Ransomware"
        $Hunter1 = "---------- Hunter Ransomware ----------"
        $Hunter2 = "Encrypted files have the .hunter extension."
        $Hunter3 = "Your files have been encrypted using Hunter Ransomware!"
        $Proton = "attack-tw1337@proton.me"
    condition:
        uint16(0) == 0x5A4D and pe.timestamp == 0 and pe.imports("kernel32.dll") and 
        $Prince and all of ($Hunter*) and $Proton
}