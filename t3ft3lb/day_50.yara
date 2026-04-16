rule info_custom_rolling_xor
{
    meta:
        description = "Detects PE files using a custom rolling XOR routine"
        author = "@t3ft3lb"
        date = "2026-02-19"
        reference = "https://www.sophos.com/en-us/blog/sharpening-the-knife-gold-blades-strategic-evolution"
        hash1 = "ab4695e5d5472af124ea69e0c1abb4c9726980b4c99c5da10ae2ba85f55bf1e4" // Red Wolf (RedCurl, GOLD BLADE, Earth Kapre) - RedLoader 1st stage
        hash2 = "e81321810a9f5058ed73edce827453442d603ca89a2de4939ce55b83e7d7ff63" // Black Myth Wukong v1.0-v1.0.20 Plus 44 Trainer.exe

    strings:
        $h = {
              2B C2                 // sub     eax, edx
              D1 E8                 // shr     eax, 1
              03 C2                 // add     eax, edx
              C1 E8 1E              // shr     eax, 1Eh
              69 C0 FF FF FF 7F     // imul    eax, 7FFFFFFFh
              44 2B C0              // sub     r8d, eax
              41 69 C8 8F BC 00 00  // imul    ecx, r8d, 0BC8Fh
              41 0F B6 C0           // movzx   eax, r8b
              41 32 42 ??           // xor     al, [r10+??]
              41 88 43 ??           // mov     [r11+??], al
              B8 03 00 00 00        // mov     eax, 3
             }
    
    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and #h > 5
}