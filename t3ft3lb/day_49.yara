rule tool_obfs4proxy_config
{
    meta:
        description = "Detects obfs4proxy configuration file containing obfs4 bridge entries"
        author = "@t3ft3lb"
        date = "2026-02-18"
        reference = "https://gitlab.com/yawning/obfs4"
        hash1 = "0ff79b5a5af723654a6a6b8ce879a0aed2b009cee93dc9a8452b7dc7608f7aae"
        hash2 = "cb96e64376f0485fb05b44a46223a6f27ba93686f8b38de7db4124898d158be2"
        hash3 = "ec80e96e3d15a215d59d1095134e7131114f669ebc406c6ea1a709003d3f6f17"

    strings:
        $r = /Bridge\s+obfs4\s+((?:\d{1,3}\.){3}\d{1,3}:\d{1,5})\s+([A-F0-9]{40})/ ascii fullword
        
        $s0 = "cert=" ascii
        $s1 = "iat-mode=" ascii

    condition:
        filesize > 400 and filesize < 4KB and
        #r > 1 and all of ($s*)
}