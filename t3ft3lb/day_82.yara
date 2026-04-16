import "pe"

rule hunt_unsigned_trueconf_installer
{
    meta:
        description = "Detects unsigned TrueConf installers"
        author = "@t3ft3lb"
        date = "2026-03-23"
        reference = "https://securelist.ru/head-mare-campaign-phantompxpigeon-backdoor-and-trueconf-software/114998/"
        hash1 = "3535c5a2a4c845c325c4db3d0d34255d8e6fa0c9ee2d03f5711e0ff89525000c"
        hash2 = "c7d86b46afd546e6ba231789859be55d83ad74225671a02fbc43bd8bee5d9214"

    strings:
        $s0 = "TrueConf Setup" wide fullword
        $s1 = "TrueConf LLC" wide fullword
        $s2 = "This installation was built with Inno Setup" wide fullword

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and
        filesize > 110MB and filesize < 220MB and
        not pe.is_signed and
        all of them
}