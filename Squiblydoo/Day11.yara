rule possible_commercial_shellcode_loader_with_decoy : malware {
   meta:
      description = "This rule detects on strings associated with a shellcode loader."
      author = "yarGen and SquiblydooBlog"
      category = "loader"
      date = "2026-01-11"
      hash1 = "c2b4214f65aaf845bb7ec37c7fe83270d5774ec3b1eafb47cc4b9f793be8c35f"
      score = 75
   strings:
      $x1 = "C:\\Users\\Infomaniak\\Desktop\\Code\\XTenia\\x64\\Release\\Tenia.pdb" fullword ascii
      $x2 = "Shellcode Executed!" fullword ascii
      $x3 = "GetModuleHandleW for ntdll.dll failed." fullword ascii
      $x4 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $x8 = "chmod +x failed"
      $x17 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii
      $x18 = "api-ms-win-core-processthreads-l1-1-2" fullword wide

      $op0 = { 48 83 ec 28 48 8d 0d 65 c2 10 00 e8 38 86 00 00 }
   condition:
      uint16(0) == 0x5a4d and (1 of ($x*)) and all of ($op*)
}
