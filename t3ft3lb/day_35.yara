rule tool_netsupport_config_client32_ini
{
    meta:
        description = "Detects NetSupport Manager configuration file client32.ini"
        author = "@t3ft3lb"
        date = "2026-02-04"
        reference = "https://kb.netsupportsoftware.com/knowledge-base/netsupport-manager-client32u-ini-explained/"
        hash1 = "1027cd7578146cafe39eacf1ed6d2048aa12fc6936d2594d49eb093c56b2d840" // Clubfoot Wolf (NetMedved)
        hash2 = "576bec03846828620fc388e9d2503d86667c622b791ae4debc5de56458390bbf" // Bloody Wolf
        hash3 = "692a547826f19109bef67a8d8d064972fc5409ae156410d31ae16bfcc67c7117" // other NetSupport RAT campaigns

    strings:
        $s0 = "[Client]" ascii fullword
        $s1 = "[_Info]" ascii fullword
        $s2 = "[_License]" ascii fullword
        $s3 = "[General]" ascii fullword
        $s4 = "[HTTP]" ascii fullword
        $s5 = "GatewayAddress" ascii fullword
        $s6 = "SecondaryGateway" ascii fullword
  
    condition:
        uint16(0) == 0x7830 and
        filesize > 400 and filesize < 1KB and
        6 of them
}