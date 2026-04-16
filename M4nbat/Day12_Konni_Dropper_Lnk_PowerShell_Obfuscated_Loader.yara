rule Dropper_PowerShell_Obfuscated_XOR_Loader {
meta:
author = "M4nbat"
description = "Detects LNK files with embedded PowerShell droppers using randomized casing and byte-level XOR extraction. Character class regex used for max compatibility."
date = "2026-01-25"
yarahub_author_twitter = "@knappresearchlb"
yarahub_reference_link = "https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/"
yarahub_reference_md5 = "1a677e0ce4c10840c09d8d414b3a8f5c "
yarahub_reference_sha256 = "39fdff2ea1a5e2b6151eccc89ca6d2df33b64e09145768442cec93a578f1760c"
yarahub_uuid = "9f2d1e4c-8b7a-4d3c-a1b2-c3d4e5f6a7b8"
yarahub_license = "CC0 1.0"
yarahub_rule_matching_tlp = "TLP:WHITE"
yarahub_rule_sharing_tlp = "TLP:WHITE"
malpedia_family = "win.dropper"

strings:
// Detects: pARaM($abc,$def,$ghi,$jkl,$mno)
$re_param = /[pP][aA][rR][aA][mM]\s*\(\$[a-zA-Z]{3},\$[a-zA-Z]{3},\$[a-zA-Z]{3},\$[a-zA-Z]{3},\$[a-zA-Z]{3}\)/

// Detects the FileStream Seek call
$re_seek = /\.s[eE]{2}k\(\$[a-zA-Z]{3},\[[sS][yY][sS][tT][eE][mM]\.[iI][oO]\.[sS][eE]{2}[kK][oO][rR][iI][gG][iI][nN]\]::[bB][eE][gG][iI][nN]\)/

// Detects the XOR loop: $abc[$def]=$abc[$def] -bxor $ghi
$re_xor = /\{\$[a-zA-Z]{3}\[\$[a-zA-Z]{3}\]=\$[a-zA-Z]{3}\[\$[a-zA-Z]{3}\]\s*-[bB][xX][oO][rR]\s*\$[a-zA-Z]{3};?\}/

// Specific string artifacts
$s1 = ".LNK" ascii wide nocase
$s2 = ".CAB" ascii wide nocase
$s3 = ".BaT" ascii wide nocase

condition:
uint16(0) == 0x004C and (2 of ($re*) and 2 of ($s*))
}
