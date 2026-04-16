rule tool_meshagent_config_msh
{
    meta:
        description = "Detects MeshAgent configuration MSH file"
        author = "@t3ft3lb"
        date = "2026-02-10"
        reference = "https://github.com/Ylianst/MeshAgent"
        hash1 = "d63ba84b146f015bc2818ab0e646defd49c8d8b4fd9d5f3a4bf57974320fe01c"
        // Rainbow Hyena (Head Mare, PhantomCore) from b350beb7f069da939aec1eef6fd428fcbc0e17edac983dc87e67716d83a04822
        hash2 = "7f8c02d36adfe530cf1e8dae088842ce87bc5c568fe434df99092450535e8c40"
        // UNC4221 from 44775029f1c2af2fab6e633678bd8087c8422dc852db67b48680b60878f7e9dd

    strings:
        $s0 = "MeshName" ascii fullword
        $s1 = "MeshType" ascii fullword
        $s2 = "MeshID" ascii fullword
        $s3 = "ServerID" ascii fullword
        $s4 = "MeshServer=wss" ascii fullword
        $s5 = "InstallFlags" ascii fullword
        $s6 = "ignoreProxyFile" ascii fullword
        $s7 = "meshServiceName" ascii fullword
        $s8 = "translation={\"en\":{\"agent\":\"Agent\",\"agentVersion\"" ascii fullword
  
    condition:
        uint16(0) == 0x0A0D and
        filesize > 27KB and filesize < 35KB and
        5 of them
}