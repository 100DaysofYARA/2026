import "pe"

rule crazy_hunters_av_killer
{
	meta:
		desc =  "AV Killer (Initial Stage Component)"
		author = "@josh_penny"
		hash = "754d5c0c494099b72c050e745dde45ee4f6195c1f559a0f3a0fddba353004db6"
		date = "2026-01-08"
	strings:
		$path = "C:/Users/fake/Desktop/ASIA/"
		$str1 = "8leaku"
		$str2 = "BADPREC)N"
		$str3 = "(BADINDEH"
		$str4 = "(MISSINGH"
		$str5 = "powrprofH"
		$str6 = "rof.dll"
	condition:
		pe.timestamp == 0 and pe.imports("kernel32.dll") and
		$path and all of ($str*)
}