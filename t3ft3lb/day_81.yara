rule tool_cloudflared_gen
{
    meta:
        description = "Detects cloudflared (Cloudflare Tunnel client) tunneling tool"
        author = "@t3ft3lb"
        date = "2026-03-22"
        reference = "https://github.com/cloudflare/cloudflared"
        hash1 = "59b12880b24af581cf5b1013db601c7d843b9b097e9c78aa5957c7f39f741885" // PE32+
        hash2 = "4a9e50e6d6d798e90fcd01933151a90bf7edd99a0a55c28ad18f2e16263a5c30" // ELF64
        hash3 = "b91dbec79a3e3809d5508b96d8b0bdfbf3ad7d51f858200228fa3e57100580d9" // Mach-O64

    strings:
        $go = "Go build" ascii

        $s0 = "cloudflared" fullword ascii
        $s1 = "cloudflareAccessCertsURL" fullword ascii
        $s2 = "ingress.NewWarpRoutingConfig" fullword ascii
        $s3 = "ingress.defaultWarpRoutingConnectTimeout" fullword ascii
        $s4 = "cloudflared connects your machine or user identity to Cloudflare's global network" fullword ascii

    condition:
        (
         (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) or
         uint32(0) == 0x464C457F or
         uint32(0) == 0xCEFAEDFE or
         uint32(0) == 0xCFFAEDFE or
         uint32(0) == 0xFEEDFACE or
         uint32(0) == 0xFEEDFACF
        ) and
        filesize > 30MB and filesize < 70MB and
        $go and 3 of ($s*)
}