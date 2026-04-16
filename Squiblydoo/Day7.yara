import "pe"

rule CRIME_SOON_TO_BE_ABUSED_CERTIFICATE : malware {
    meta:
        name        = "soon to be abused"
        category    = "installer"
        description = "This YARA rule detects PE files using the codesigning certificate for Xiamen Jialan Guang Information Technology Service Co., Ltd."
        author      = "SquiblydooBlog"
        created     = "2026-01-07"
        reliability = 100
        tlp         = "TLP:clear"
        sample      = "a4380e9ac13668d4ff6fc30fdc1efcbfba9e6c1d73bbc994dba34bef605086fc"

    condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.subject contains "Xiamen Jialan Guang Information Technology Service Co., Ltd." and 
		 sig.serial == "22:75:63:ec:cf:59:cb:d7:e3:e7:c8:73:1b:66:61:94"
      )
}
