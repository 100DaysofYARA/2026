rule pckr_rustpacker_pe
{
    meta:
        description = "Detects PE files packed with RustPacker, a template-based shellcode packer with indirect syscall support"
        author = "@t3ft3lb"
        date = "2026-01-23"
        reference = "https://github.com/Nariod/RustPacker"
        hash1 = "b969a6643462c192c2f1b90c9541a4bcc4456d18c597117ad1a0e0f44fa24ac2"
        hash2 = "745d10c9ae40e4ee1f511e1b0b8ae68c557548c8b4b5a8e1b90178a96cccec45"
        hash3 = "d89943cd164b8020c6524263625192dc0c0291eea871a427ea309f009cca30fc"

    strings:
        $rust = "rustc" ascii fullword

        $s0 = "[-] Unable to find a process." ascii
        $s1 = "[-] Failed to call NtProtectVirtualMemory:" ascii
        $s2 = "[!] ConvertThreadToFiber Failed With Error:" ascii
        $s3 = "[!] CreateFiber Failed With Error:" ascii
        $s4 = "Error allocating memory to the target process:" ascii
        $s5 = "Error allocating memory to the local process:" ascii
        $s6 = "Error writing to the target process:" ascii
        $s7 = "Error writing to the local process:" ascii
        $s8 = "Error failed to create remote thread:" ascii
        $s9 = "Error opening process:" ascii

        $h0 = { 41 C1 E9 0E 41 81 E1 FC 03 00 00 }
        $h1 = { 41 C1 E? 18 41 C1 E? 0E }
        $h2 = { C1 E? 0E B? FC 03 00 00 }
        $h3 = { C1 EA 0E 81 E2 FC 03 00 00 }
        $h4 = { C1 E? 18 C1 E? 10 C1 E? 08 }
        $h5 = { C1 E? 18 C1 E? 10 41 C1 E? 08 }

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and
        #rust > 10 and 4 of ($s*) and 3 of ($h*)
}