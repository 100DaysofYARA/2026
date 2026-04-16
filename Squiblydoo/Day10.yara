rule mcrit_havoc_w_decoy_loader : malicious {
    meta:
        author = "MCRIT YARA Generator"
		category = "loader"
        description = "Code-based YARA rule composed from potentially unique basic blocks for the selected set of samples/family."
        date = "2026-01-10"
    strings:
        // Rule generation selected 10 picblocks, covering 1/1 input sample(s).
        /* picblockhash: 0xe1ef788b12bc298e - coverage: 1/1 samples.
         * 4d8d480f         | lea r9, [r8 + 0xf]
         * 4983e1f0         | and r9, 0xfffffffffffffff0
         * 4d8bd9           | mov r11, r9
         * 49c1eb04         | shr r11, 4
         * 478b9c9a48701000 | mov r11d, dword ptr [r10 + r11*4 + 0x107048]
         * 4d03da           | add r11, r10
         * 41ffe3           | jmp r11
         */
        $blockhash_0xe1ef788b12bc298e = {
            4d8d480f 4983e1f0 4d8bd9 49c1eb04 478b9c9a48701000 4d03da 41ffe3
        }

        /* picblockhash: 0xed4b20057559f931 - coverage: 1/1 samples.
         * 4d8d481f         | lea r9, [r8 + 0x1f]
         * 4983e1e0         | and r9, 0xffffffffffffffe0
         * 4d8bd9           | mov r11, r9
         * 49c1eb05         | shr r11, 5
         * 478b9c9ab0701000 | mov r11d, dword ptr [r10 + r11*4 + 0x1070b0]
         * 4d03da           | add r11, r10
         * 41ffe3           | jmp r11
         */
        $blockhash_0xed4b20057559f931 = {
            4d8d481f 4983e1e0 4d8bd9 49c1eb05 478b9c9ab0701000 4d03da 41ffe3
        }

        /* picblockhash: 0xc0df35bb82f21028 - coverage: 1/1 samples.
         * 4d8d481f         | lea r9, [r8 + 0x1f]
         * 4983e1e0         | and r9, 0xffffffffffffffe0
         * 4d8bd9           | mov r11, r9
         * 49c1eb05         | shr r11, 5
         * 478b9c9ad4701000 | mov r11d, dword ptr [r10 + r11*4 + 0x1070d4]
         * 4d03da           | add r11, r10
         * 41ffe3           | jmp r11
         */
        $blockhash_0xc0df35bb82f21028 = {
            4d8d481f 4983e1e0 4d8bd9 49c1eb05 478b9c9ad4701000 4d03da 41ffe3
        }

        /* picblockhash: 0xc69d233c0c9d0a36 - coverage: 1/1 samples.
         * 4d8d480f         | lea r9, [r8 + 0xf]
         * 4983e1f0         | and r9, 0xfffffffffffffff0
         * 4d8bd9           | mov r11, r9
         * 49c1eb04         | shr r11, 4
         * 478b9c9af8701000 | mov r11d, dword ptr [r10 + r11*4 + 0x1070f8]
         * 4d03da           | add r11, r10
         * 41ffe3           | jmp r11
         */
        $blockhash_0xc69d233c0c9d0a36 = {
            4d8d480f 4983e1f0 4d8bd9 49c1eb04 478b9c9af8701000 4d03da 41ffe3
        }

        /* picblockhash: 0x8e81798f1ab2c5b3 - coverage: 1/1 samples.
         * 4053     | push rbx
         * 55       | push rbp
         * 4883ec28 | sub rsp, 0x28
         * 488bea   | mov rbp, rdx
         * 48894d30 | mov qword ptr [rbp + 0x30], rcx
         * 807d5800 | cmp byte ptr [rbp + 0x58], 0
         * 746c     | je 0x14002c08c
         */
        $blockhash_0x8e81798f1ab2c5b3 = {
            4053 55 4883ec28 488bea 48894d30 807d5800 74??
        }

        /* picblockhash: 0x6086a984ea0ddc61 - coverage: 1/1 samples.
         * 4055           | push rbp
         * 4883ec20       | sub rsp, 0x20
         * 488bea         | mov rbp, rdx
         * 4c8d4520       | lea r8, [rbp + 0x20]
         * 488b95d8000000 | mov rdx, qword ptr [rbp + 0xd8]
         * e87546feff     | call 0x140010748
         * 90             | nop 
         * 4883c420       | add rsp, 0x20
         * 5d             | pop rbp
         * c3             | ret 
         */
        $blockhash_0x6086a984ea0ddc61 = {
            4055 4883ec20 488bea 4c8d4520 488b95d8000000 e8???????? 90 4883c420 5d c3
        }

        /* picblockhash: 0x46824eb427d0f42c - coverage: 1/1 samples.
         * 4053       | push rbx
         * 55         | push rbp
         * 4883ec28   | sub rsp, 0x28
         * 488bea     | mov rbp, rdx
         * 488b4d30   | mov rcx, qword ptr [rbp + 0x30]
         * e89e15feff | call 0x14000d68c
         * 837d2000   | cmp dword ptr [rbp + 0x20], 0
         * 7548       | jne 0x14002c13c
         */
        $blockhash_0x46824eb427d0f42c = {
            4053 55 4883ec28 488bea 488b4d30 e8???????? 837d2000 75??
        }

        /* picblockhash: 0x842a46040f858813 - coverage: 1/1 samples.
         * e8e31cfeff | call 0x14000de24
         * 488b4d70   | mov rcx, qword ptr [rbp + 0x70]
         * 48894820   | mov qword ptr [rax + 0x20], rcx
         * e8d61cfeff | call 0x14000de24
         * 488b4d78   | mov rcx, qword ptr [rbp + 0x78]
         * 48894828   | mov qword ptr [rax + 0x28], rcx
         * 4883c428   | add rsp, 0x28
         * 5d         | pop rbp
         * 5b         | pop rbx
         * c3         | ret 
         */
        $blockhash_0x842a46040f858813 = {
            e8???????? 488b4d70 48894820 e8???????? 488b4d78 48894828 4883c428 5d 5b c3
        }

        /* picblockhash: 0x23915fc2b826e93c - coverage: 1/1 samples.
         * 4055           | push rbp
         * 4883ec20       | sub rsp, 0x20
         * 488bea         | mov rbp, rdx
         * 4c8d4d20       | lea r9, [rbp + 0x20]
         * 448b85f0000000 | mov r8d, dword ptr [rbp + 0xf0]
         * 488b5528       | mov rdx, qword ptr [rbp + 0x28]
         * e85546feff     | call 0x1400107d0
         * 90             | nop 
         * 4883c420       | add rsp, 0x20
         * 5d             | pop rbp
         * c3             | ret 
         */
        $blockhash_0x23915fc2b826e93c = {
            4055 4883ec20 488bea 4c8d4d20 448b85f0000000 488b5528 e8???????? 90 4883c420 5d
            c3
        }

        /* picblockhash: 0x74dfb11f1134d8a6 - coverage: 1/1 samples.
         * 4055         | push rbp
         * 4883ec20     | sub rsp, 0x20
         * 488bea       | mov rbp, rdx
         * 488b01       | mov rax, qword ptr [rcx]
         * 8b08         | mov ecx, dword ptr [rax]
         * 81f9050000c0 | cmp ecx, 0xc0000005
         * 740c         | je 0x14002c532
         */
        $blockhash_0x74dfb11f1134d8a6 = {
            4055 4883ec20 488bea 488b01 8b08 81f9050000c0 74??
        }

    condition:
        7 of them
}