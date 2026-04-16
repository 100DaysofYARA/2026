rule trashagent_process_list_check : malware {
    meta:
        name        = "trashagent_process_list_check"
        category    = "evasion"
        description = "TrashAgent malware contains a hardcoded list of processes to check for on a system. It identifies the list and then separates the list before querying for the running processes. The processes are mostly enterprise or chat applications. This only detects a subset of TrashAgent. The detected version uses mscvrt but the version using vcruntime140 is not covered in this rule."
        author      = "SquiblydooBlog"
        created     = "2026-01-01"
        reliability = 90
        tlp         = "TLP:clear"
        sample      = "3479e83b351739cbea33905de5236af5e66ca3f8edc1b8d972551d93b3f13891"

    strings:
		/*
         * 0FB647??                 | movzx        eax, byte ptr [rdi-0x02]
         * 3CC0                     | cmp          al, 0xC0
         * 7D??                     | jnl          0x14000D074
         * 0FB64F??                 | movzx        ecx, byte ptr [rdi-0x03]
         * 80F9BF                   | cmp          cl, 0xBF
         * 7F??                     | jnle         0x14000D07D
         * 0FB657??                 | movzx        edx, byte ptr [rdi-0x04]
         * 4883C7FC                 | add          rdi, 0xFFFFFFFFFFFFFFFC
         * 83E207                   | and          edx, 0x07
         * C1E206                   | shl          edx, 0x06
         * 83E13F                   | and          ecx, 0x3F
         * 09D1                     | or           ecx, edx
         * EB??                     | jmp          0x14000D084
         * 4883C7FE                 | add          rdi, 0xFFFFFFFFFFFFFFFE
         * 83E01F                   | and          eax, 0x1F
         * EB??                     | jmp          0x14000D08C
         * 4883C7FD                 | add          rdi, 0xFFFFFFFFFFFFFFFD
         * 83E10F                   | and          ecx, 0x0F
         * C1E106                   | shl          ecx, 0x06
         * 83E03F                   | and          eax, 0x3F
         * 09C8                     | or           eax, ecx
        */
        $process_list_prep_v1 = { 0FB647?? 3CC0 7D?? 0FB64F?? 80F9BF 7F?? 0FB657?? 4883C7FC 83E207 C1E206 83E13F 09D1 EB?? 4883C7FE 83E01F EB?? 4883C7FD 83E10F C1E106 83E03F 09C8 }
        /*
         * 89C1                     | mov          ecx, eax
         * C1E106                   | shl          ecx, 0x06
         * 83E53F                   | and          ebp, 0x3F
         * 09CD                     | or           ebp, ecx
         * 81FD00001100             | cmp          ebp, 0x110000
        */
        $process_process_list_v1 = { 89C1 C1E106 83E53F 09CD 81FD00001100 }   

/*
         * 410FB648??               | movzx        ecx, byte ptr [r8-0x02]
         * 80F9C0                   | cmp          cl, 0xC0
         * 7D??                     | jnl          0x14000C6FF
         * 450FB648??               | movzx        r9d, byte ptr [r8-0x03]
         * 4180F9BF                 | cmp          r9b, 0xBF
         * 7F??                     | jnle         0x14000C708
         * 450FB650??               | movzx        r10d, byte ptr [r8-0x04]
         * 4983C0FC                 | add          r8, 0xFFFFFFFFFFFFFFFC
         * 4183E207                 | and          r10d, 0x07
         * 41C1E206                 | shl          r10d, 0x06
         * 4183E13F                 | and          r9d, 0x3F
         * 4509D1                   | or           r9d, r10d
         * EB??                     | jmp          0x14000C710
         * 4983C0FE                 | add          r8, 0xFFFFFFFFFFFFFFFE
         * 83E11F                   | and          ecx, 0x1F
         * EB??                     | jmp          0x14000C71A
         * 4983C0FD                 | add          r8, 0xFFFFFFFFFFFFFFFD
         * 4183E10F                 | and          r9d, 0x0F
         * 41C1E106                 | shl          r9d, 0x06
         * 83E13F                   | and          ecx, 0x3F
         * 4409C9                   | or           ecx, r9d
        */
        $process_list_prep_v2 = { 410FB648?? 80F9C0 7D?? 450FB648?? 4180F9BF 7F?? 450FB650?? 4983C0FC 4183E207 41C1E206 4183E13F 4509D1 EB?? 4983C0FE 83E11F EB?? 4983C0FD 4183E10F 41C1E106 83E13F 4409C9 }
        /*
         * 4189C9                   | mov          r9d, ecx
         * 41C1E106                 | shl          r9d, 0x06
         * 83E53F                   | and          ebp, 0x3F
         * 4409CD                   | or           ebp, r9d
         * 81FD00001100             | cmp          ebp, 0x110000
        */
        $process_process_list_v2 = { 4189C9 41C1E106 83E53F 4409CD 81FD00001100 }


        /*
         * 0FBE57??                 | movsx        edx, byte ptr [rdi-0x01]
         * 85D2                     | test         edx, edx
         * 78??                     | js           0x14000568C
         * 48FFCF                   | dec          rdi
         * EB??                     | jmp          0x1400056DE
         * 0FB647??                 | movzx        eax, byte ptr [rdi-0x02]
         * 3CC0                     | cmp          al, 0xC0
         * 7D??                     | jnl          0x1400056B6
         * 0FB64F??                 | movzx        ecx, byte ptr [rdi-0x03]
         * 80F9BF                   | cmp          cl, 0xBF
         * 7F??                     | jnle         0x1400056BF
         * 440FB647??               | movzx        r8d, byte ptr [rdi-0x04]
         * 4883C7FC                 | add          rdi, 0xFFFFFFFFFFFFFFFC
         * 4183E007                 | and          r8d, 0x07
         * 41C1E006                 | shl          r8d, 0x06
         * 83E13F                   | and          ecx, 0x3F
         * 4409C1                   | or           ecx, r8d
         * EB??                     | jmp          0x1400056C6
         * 4883C7FE                 | add          rdi, 0xFFFFFFFFFFFFFFFE
         * 83E01F                   | and          eax, 0x1F
         * EB??                     | jmp          0x1400056CE
        */
        $process_list_prep_v3 = { 0FBE57?? 85D2 78?? 48FFCF EB?? 0FB647?? 3CC0 7D?? 0FB64F?? 80F9BF 7F?? 440FB647?? 4883C7FC 4183E007 41C1E006 83E13F 4409C1 EB?? 4883C7FE 83E01F EB?? }

        /*
         * 4883C7FD                 | add          rdi, 0xFFFFFFFFFFFFFFFD
         * 83E10F                   | and          ecx, 0x0F
         * C1E106                   | shl          ecx, 0x06
         * 83E03F                   | and          eax, 0x3F
         * 09C8                     | or           eax, ecx
         * C1E006                   | shl          eax, 0x06
         * 83E23F                   | and          edx, 0x3F
         * 09C2                     | or           edx, eax
        */
        $process_process_list_v3 = { 4883C7FD 83E10F C1E106 83E03F 09C8 C1E006 83E23F 09C2 }

    condition:
        ($process_list_prep_v1 and $process_process_list_v1) or ($process_list_prep_v2 and $process_process_list_v2) or ($process_list_prep_v3 and $process_process_list_v3)
}