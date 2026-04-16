rule ta_forgery_werewolf_zagrebator_pdb
{
    meta:
        description = "Detects Forgery Werewolf (FakeTicketer) Zagrebator malware based on PDB path pattern"
        author = "@t3ft3lb"
        date = "2026-03-15"
        reference = "https://habr.com/ru/companies/F6/news/874046/"
        hash1 = "0d41414c3eedaa62f4c8733204432fe93c66fec7320843ffcc66fb04497864e6" // Zagrebator.Dropper
        hash2 = "3b5ecd89ae691e1bfcbe20d9a31f38cb98c63cea076336982f9d04d74d80231c" // Zagrebator.RAT
        hash3 = "d5c6af702f225c218bda9f4ef2d2c2dbd64b7f834b939d66e75c47b94df46b6b" // Zagrebator.Stealer

    strings:
        $dotnet = ".NETFramework" ascii fullword
        $pdb_path = "MODULI\\ZAGRIBATOR" ascii fullword

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and
        filesize > 10KB and filesize < 7MB and
        $dotnet and $pdb_path
}