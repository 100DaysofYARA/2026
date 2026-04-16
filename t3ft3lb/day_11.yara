rule ta_rattling_werewolf_document_xml_rels
{
    meta:
        description = "Detects document.xml.rels files associated with Rattling Werewolf (SideWinder)"
        author = "@t3ft3lb"
        date = "2026-01-11"
        reference = "https://www.group-ib.com/blog/hunting-sidewinder/"
        hash1 = "99ed9f44a02a3549d60c58233f793622319ed4d08d2c1c8d6fd17fcb06afa8c0" // hxxps://pmo-gov-pk.snagdrive[.]com/17441/1/38669/2/32/0/0/m/files-8e4de920/Font_Updates.rtf
        hash2 = "d92961b536f1f8229208b2cd8c099dfaae67219ea6b55cd58e7c90daa4d8fc52" // hxxps://nomination.info-bdgov[.]com/5123/1/51969/2/32/0/0/m/files-d9fb640e/MSFT_CLD_Font.rtf
        hash3 = "c0b4d57dd0a8fe415b35ee452818a6ffe695c75d559bd92324771d9f663ebe14" // hxxps://invitation.army-lk[.]info/5103/1/54424/2/32/0/0/m/files-745e58fd/MSFT_CLD_Font.rtf

    strings:
        $s0 = "Relationship Id" ascii fullword
        $s1 = "TargetMode=\"External\"" ascii fullword

        $r = /\/0\/0\/m\/files-[0-9a-fA-F]{8}\// ascii

    condition:
        uint32(0) == 0x6D783F3C and
        all of them
}