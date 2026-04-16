rule Danabot
{
    meta:
	    desc = "Detects Danabot"
	    author = "Joshua Penny"
	    hash = "0fdbbac16d49a7e6cce0a463d66aa2d47780c35fbfc9d3d78abd34519d23cbab"
		date = "2026-01-05"
    strings:
	    $onion1 = "aqpfkxxtvahlzr6vobt6fhj4riev7wxzoxwltbcysuybirygxzvp23ad.onion" wide
	    $onion2 = "t77e4phezpwqebpbhdagr26ewkfaxytscimhxofws4wcisjo4wundead.onion" wide
	    $onion3 = "vsjyfpt7vcd6atniefmz36ikxrqk5eyv573a2af4e2ntb437wdch63yd.onion" wide
	    $onion4 = "fejdqikkdwheckrutucbbyeovpdnef4bopz2fx636i67p3qpffpfxxad.onion" wide
	
	    $path1 = "Z:\\release\\FS_www\\" nocase wide
	    $path_danabot1 = "DanaBot_64" nocase fullword wide
	    $path_danabot2 = "DanaExeLoader" nocase fullword wide
    condition:
	uint16be(0) == 0x4D5A and 
        (any of ($onion*) or 
        ($path1 and any of ($path_danabot*)))
}