rule mal_callisto
{
    meta:
        author = "manb4t"
        description = "string based detection for Callisto (Star Blizzard) malware"
        sha256 = "37c52481711631a5c73a6341bd8bea302ad57f02199db7624b580058547fb5a9"
    strings:
        $str1 = "text here" wide
        $str2 = "SystemDriveUSERNAMEUsersAppDataagent\\src\\command\\cookie\\browser\\mod.rs" wide
        $str2 = "SystemDriveUSERNAMEUsersAppDataagent\\src\\command\\cookie\\browser\\mod.rs" wide
        $str2 = "/tnCalendarChecker/queryschtasks" wide
        $regex1 = / [0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\:3000 / wide
    condition:
        3 of $str* and $regex1
}
