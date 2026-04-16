import "pe"

rule Rhysida_CRIME_WIN_PACKER: malware
{
    meta:
        name = "2025-06 Oyster packer rich header and imports"
        category = "packer"
        created = "2025-06-19"
        revision = "1"
        description = "Detects packer used with recent Oyster loader and implant."
        author = "@SquiblydooBlog"
        tlp = "TLP:clear"
        reliability = 100
        sample = "daa4ca6b3a4d567eac51b70921a9d6254884477bf5454f966d0ef412c6f0e443"
        sample = "cd671cfa42714a6d517476add60690081a16a5c6abaacce25fcb9c5ddf41b7d3"

    condition:
        pe.number_of_signatures > 0 and
        pe.rich_signature.toolid(0x103, 0x784b) >= 2 and    // MASM x2
        pe.rich_signature.toolid(0x105, 0x784b) >= 1 and    // CPP
        pe.rich_signature.toolid(0x104, 0x784b) >= 1 and    // C
        pe.rich_signature.toolid(0x103, 0x8611) >= 1 and    // A second MASM
        pe.rich_signature.toolid(0x104, 0x8611) >= 1 and    // A second C
        pe.rich_signature.toolid(0x105, 0x8611) >= 1 and    // A second CPP
        pe.rich_signature.toolid(0x101, 0x784b) >= 1 and    // Implib
        pe.rich_signature.toolid(0x105, 0x87f9) >= 1 and    // A third CPP
        pe.rich_signature.toolid(0xff, 0x87f9) >= 1 and     // Cvtres
        pe.rich_signature.toolid(0x102, 0x87f9) and         // Linker     
        pe.imports("user32.dll")==5 and
        pe.imports("gdi32.dll")==24     
}