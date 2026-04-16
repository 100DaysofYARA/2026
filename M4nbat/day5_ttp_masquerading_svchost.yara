import "pe"
rule ttp_masquerading_svchost_pdb_path_not_svchost {
    meta:
        author = "manb4t"
    condition:
        pe.pdb_path != "svchost.pdb" and
        pe.characteristics > 100
}   
rule TTP_VersionInfo_Svchost_Has_C_Users_String {
	meta:
		desc = "Anything with svchost in the VersionInfo with C:\\Users path"
		ref = "D723B7C150427A83D8A08DC613F68675690FA0F5B10287B078F7E8D50D1A363F"
	strings:
		$s = "C:\\Users\\"
	condition:
		(
			pe.version_info["InternalName"] icontains "svchost" or
			pe.version_info["OriginalFilename"] icontains "svchost"
		)
	and $s
}
rule TTP_VersionInfo_Svchost_Manifest_Mismatch {
	meta:
		desc = "Anything with svchost in the VersionInfo"
		ref = "D723B7C150427A83D8A08DC613F68675690FA0F5B10287B078F7E8D50D1A363F"
	strings:
		$a1 = "<!-- Copyright (c) Microsoft Corporation -->"
		$a2 = "name=\"Microsoft.Windows.Services.SvcHost\""
		$a3 = "<description>Host Process for Windows Services</description>"
	condition:
		(
			pe.version_info["InternalName"] icontains "svchost" or
			pe.version_info["OriginalFilename"] icontains "svchost"
		)
		and not any of ($a*)
}
rule TTP_VersionInfo_Svchost_Giant_Filesize {
	meta:
		desc = "Anything with svchost in the VersionInfo"
		ref = "D723B7C150427A83D8A08DC613F68675690FA0F5B10287B078F7E8D50D1A363F"
	condition:
		filesize > 2MB
		and (
			pe.version_info["InternalName"] icontains "svchost" or
			pe.version_info["OriginalFilename"] icontains "svchost"
			)
}
