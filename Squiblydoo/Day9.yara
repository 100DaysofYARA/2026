
rule blue_noroff_MACOS_initial_access_script : malware {
    meta:
        name        = "initial script lure header"
        category    = "installer"
        description = "This is a common header of a .SCPT file used to target MacOS systems for initial access."
        author      = "SquiblydooBlog"
        created     = "2026-01-10"
        reliability = 100
        tlp         = "TLP:clear"
        sample      = "1833667cbb97f40d5f4ea101c6cb4432089c9d9dced9d96788dfb49ac7f30eae"

    strings:
        $common_header = "###############################################################\n#\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t#\n#\t\t\t\t\t\t\t\tZoom Meeting SDK Support\t\t\t\t\t\t\t\t#\n# \t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t#\n#\t\t\t\t\tA new version of the Zoom Web App will be released soon.\t\t\t\t#\n#\t\t\t\tIn the meantime, you can upgrade the Zoom Meeting SDK manually.\t\t\t#\n#\t\t\t\t\t\t\t\tPress \xE2\x96\xB6\xEF\xB8\x8F to start the upgrade.\t\t\t\t\t\t\t#\n#\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t#\n#\t\t\t\t\t\t\tCopyright (c) 2025 Zoom Community\t\t\t\t\t\t\t#\n#\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t#\n###############################################################"

    condition:
        $common_header at 0
}
