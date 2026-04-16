import "pe"

rule axolotl_loader : malware {
    meta:
        name        = "function"
        category    = "persistence"
        description = "Detects the XOR decryption loop uses by AxolotlLoader"
        author      = "SquiblydooBlog"
        created     = "2026-02-22"
        reliability = 100
        tlp         = "TLP:CLEAER"
        sample      = "5ce2c6a2eb3ebd2f66d72cdbeec4c98ce507b0bc317c5beedd61053b4f871e75"
    strings:
        /*
         * Repeating-XOR decryption loop, confirmed identical across samples.
         *
         * The routine decrypts an encrypted PE payload stored inside a PNG
         * resource (appended after the PNG IEND chunk) using a fixed-length
         * repeating key.  Key wrapping is implemented with a CMOVE so that
         * when the key pointer (RCX) reaches the key end (R10) it is reset
         * to the key start (R9).
         *
         * Disassembly (x86-64):
         *   loop_start:
         *     4C 39 D1           cmp  r10, rcx       ; key-end boundary reached?
         *     49 0F 44 C9        cmove rcx, r9        ; if so, wrap key ptr to start
         *     48 0F B6 01        movzx rax, byte [rcx]; load next key byte
         *     30 02              xor   [rdx], al      ; XOR one ciphertext byte
         *     48 83 C2 01        add   rdx, 1         ; advance data ptr
         *     48 83 C1 01        add   rcx, 1         ; advance key ptr
         *     4C 39 C2           cmp   r8, rdx        ; end of ciphertext?
         *     72 E6              jb    loop_start      ; loop (-26 bytes)
         *
         * Register roles:
         *   RCX / R9  = current / start of key buffer
         *   R10       = one-past-end of key buffer (key length = R10 - R9)
         *   RDX       = current ciphertext byte pointer
         *   R8        = one-past-end of ciphertext
         */
        $xor_loop = {
            4C 39 D1          // cmp  r10, rcx
            49 0F 44 C9       // cmove rcx, r9
            48 0F B6 01       // movzx rax, byte [rcx]
            30 02             // xor   byte [rdx], al
            48 83 C2 01       // add   rdx, 1
            48 83 C1 01       // add   rcx, 1
            4C 39 C2          // cmp   r8, rdx
            72 E6             // jb    loop_start
        }

    condition:
        uint16(0) == 0x5A4D
        // Core: the repeating-XOR loop with key-wrap CMOVE — present in all
        // observed samples, byte-identical regardless of surrounding obfuscation
        and $xor_loop
}

