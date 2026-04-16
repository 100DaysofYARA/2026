rule voidlink_implant : malware {
    meta:
        name        = "voidlink_implant"
        category    = "persistence"
        description = "Detects strings which are a part of the VoidLink implant."
        author      = "SquiblydooBlog"
        created     = "2026-01-16"
        reliability = 50
        tlp         = "TLP:CLEAR"
		reference   = "https://research.checkpoint.com/2026/voidlink-the-cloud-native-malware-framework/"
        sample1     = "15cb93d38b0a4bd931434a501d8308739326ce482da5158eb657b0af0fa7ba49"      
        sample2     = "05eac3663d47a29da0d32f67e10d161f831138e10958dcd88b9dc97038948f69"
        sample3     = "28c4a4df27f7ce8ced69476cc7923cf56625928a7b4530bc7b484eec67fe3943"
        sample4     = "4c4201cc1278da615bacf48deef461bf26c343f8cbb2d8596788b41829a39f3f"
        sample5     = "6850788b9c76042e0e29a318f65fceb574083ed3ec39a34bc64a1292f4586b41"
        sample6     = "6dcfe9f66d3aef1efd7007c588a59f69e5cd61b7a8eca1fb89a84b8ccef13a2b"

    strings:
        $credential_theft_1 = "total_harvests\""
		$credential_theft_2 = ".git-credentials"
		$credential_theft_3 = "\"ssh_config_found"

		$debugging_1 = "failed to kill process" fullword ascii
		$debugging_2 = "ProcessAlreadyExec" fullword ascii
		$debugging_3 = "Failed to connect to C2" fullword ascii
		$debugging_4 = "error: [ChainExecutor] Failed to spawn shell: error: [ChainExecutor] Failed to wait for shell: " fullword ascii

		$stealth_1 = "stealth_manager" fullword ascii
		$stealth_2 = "stealth features failed" fullword ascii
		$stealth_3 = "Stealth activation failed" fullword ascii

    condition:
        uint16(0) == 0x457f and filesize < 6000KB and all of ($credential_theft*) and 3 of ($debugging*) and 1 of ($stealth*)
}