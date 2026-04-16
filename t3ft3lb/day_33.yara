rule mlwr_custom_loader_metasploit_cobaltsrike_havoc
{
    meta:
        description = "Detects custom loader for Metasploit, Cobalt Strike, and Havoc implants"
        author = "@t3ft3lb"
        date = "2026-02-02"
        reference = "https://bi.zone/eng/expertise/blog/khaos-v-kiberprostranstve-gruppirovki-eksperimentiruyut-s-instrumentami/"
        hash1 = "ac301b7698ac040f219eb8dfb248595a406b075d91f51116ef60d4dd9f5242ad" // payload: Havoc Demon
        hash2 = "5edcb3812942ad266c2d8d980aa9c806a3b7ee68b9dc4676bbcdbe0f9addaa95" // payload: Metasploit Stager
        hash3 = "7be3b394dba1417d469ef71f13f1608a8914021ee44f1d5d38aec63f93b0faec" // payload: Cobalt Strike Stager

    strings:
        $code = {
            0F 1F 40 ??                     // 0F1F4000               nop dword ptr [rax]
            66 66 0F 1F 84 00 ?? ?? 00 00   // 66660F1F840000000000   nop word ptr [rax + rax]
            69 C0 13 73 00 00               // 69C013730000           imul eax, eax, 0x7313
            48 8D 52 ??                     // 488D5201               lea rdx, [rdx + 1]
            0F BE C9                        // 0FBEC9                 movsx ecx, cl
            03 C1                           // 03C1                   add eax, ecx
            0F B6 0A                        // 0FB60A                 movzx ecx, byte ptr [rdx]
            84 C9                           // 84C9                   test cl, cl
            75 ??                           // 75EA                   jne 0x140001230
            35 98 AB 00 00                  // 3598AB0000             xor eax, 0xab98
        }

        $ipv6 = /[0-9A-F]{4}(?::[0-9A-F]{4}){7}/ ascii fullword
  
    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and
        filesize > 4KB and filesize < 350KB and
        $code and #ipv6 > 30
}