import "pe"

rule PHALT_BLYX_DCRAT
{
	meta:
		desc = "Detects DCRAT samples used in the PhaltBlyx campaign, specifically identifying Stub.exe samples with pe stomping of the creation date."
		author = "Joshua Penny"
		hash = "bf374d8e2a37ff28b4dc9338b45bbf396b8bf088449d05f00aba3c39c54a3731"
		date = "2025-01-06"
		reference = "https://www.securonix.com/blog/analyzing-phaltblyx-how-fake-bsods-and-trusted-build-tools-are-used-to-construct-a-malware-infection/"
	strings:
		$packer = "costura"		
		$path1 = "C:\\Windows\\Temp" wide
		$path2 = "URL=file:///" wide
		
	condition:
		uint16(0) == 0x5A4D and
		pe.timestamp == 3923483659 and // Fri Apr 30 16:34:19 2094
		#packer > 10 and
		all of ($path*) and
		filesize < 2MB and
		pe.imports("mscoree.dll")
}