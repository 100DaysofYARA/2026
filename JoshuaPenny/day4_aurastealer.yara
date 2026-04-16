import "pe"

rule AuraStealer
{
	meta:
		desc = "Detects AuraStealer"
		author = "Joshua Penny"
		hash = "f7d0f099d042de83aa2d0a13100640bea49d28c77c2eb3087c0fb43ec0cd83d7"
	strings:
		$str1 = "APPBKEYREAD"	
		$str2 = "APPBKEYWRITE"
		$str3 = "BROWSERTYPE"
	condition:
		uint16(0) == 0x5A4D and 
		all of ($str*) and
		pe.imports("kernel32.dll") and pe.imports("gdiplus.dll") and
		pe.imports("ADVAPI32.dll") and
        filesize < 2MB
}