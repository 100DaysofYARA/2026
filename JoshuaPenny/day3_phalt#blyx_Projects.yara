rule MSBuild_Proj_Exclusions_and_Russian_text {
    meta:
        desc = "Detects Suspicious Project files with Russian Messages, XML Header Matching and Windows Defender Exclusions"
		author = "Joshua Penny"
		date = "2025-01-06"
		reference = "https://www.securonix.com/blog/analyzing-phaltblyx-how-fake-bsods-and-trusted-build-tools-are-used-to-construct-a-malware-infection/"

    strings:
        // Match "<? xml" or "<?xml"
        $xml = "<? xml" nocase
        $xml_std = "<?xml" nocase
        
        // Match Project tag
        $proj_tag = "<Project ToolsVersion" nocase
        
        // Exclusions and flags to disable Realtime Monitoring
        $def_exclude_path = "Add-MpPreference -ExclusionPath" nocase
        $def_exclude_ext = "Add-MpPreference -ExclusionExtension" nocase
        $def_disable_real_mon = "Set-MpPreference -DisableRealtimeMonitoring 1" nocase

        // Russian texts related to success/failure of file installation
        $msg_mixed_success = "ycTaHoBka ycnewHo" nocase                     // Installation successful
        $msg_mixed_fail = "Popытka ycTaHoBka не yдaлacь" nocase             // Attempt failed
        $msg_mixed_cancel = "YCTAHOBKA OTMEHEHA" nocase                     // Installation cancelled
        $msg_cyrillic_fail = "Попытка $attempt не удалась" wide ascii       // Attempt failed
        $msg_cyrillic_cancel = "Установка отменена" wide ascii              // Installation cancelled
        $msg_cyrillic_success = "Установка успешно завершена" wide ascii    // Installation completed successfully

    condition:
        ($xml in (0..256) or $xml_std in (0..256)) and                      // Look for headers in the first 256 bytes
        $proj_tag in (0..1024) and                                          // AND match the Project tag within the first 1KB (in case of comments)
        (
            any of ($def_*)                                                 // Exclusions
            or
            any of ($msg_*)                                                 // Russian phrases
        ) 
        and filesize < 1MB                                                  // Filesize check
}