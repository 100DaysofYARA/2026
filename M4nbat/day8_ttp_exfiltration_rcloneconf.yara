rule ttp_exfiltration_rcloneconf_exe
{
    meta:
        description = "<add description>"
        author = "Yara Toolkit"
        source = "<add source of report if any>"
        hash = ""
    strings:
        $str1 = "/sbin/mount.rclone" fullword nocase ascii
        $str2 = "/usr/bin/rclone" fullword nocase ascii
        $str3 = "github.com/rclone/rclone" fullword nocase ascii
        $str4 = "mount sftp1:subdir /mnt/data -t rclone" fullword nocase ascii
        $str5 = "Type=rclone" fullword nocase ascii
        $str6 = "ln -s /usr/bin/rclone /sbin/mount.rclone" fullword nocase ascii
        $str7 = "type:.eq.github.com/rclone/rclone" fullword nocase ascii
        $str8 = "${RCLONE_CONFIG_DIR}" fullword nocase ascii
        $str9 = "IMPORTANT: Due to Google policy changes rclone can now only download photos it uploaded" fullword nocase ascii
        $str10 = "github.com/rclone/rclone/fs.Bits[github.com/rclone/rclone" fullword nocase ascii
    condition:
        all of them and
        uint16(0) == 0x5A4D
}

rule ttp_exfiltration_rcloneconf {
    meta:
        author = "m4nbt"
        sha256 = "D723B7C150427A83D8A08DC613F68675690FA0F5B10287B078F7E8D50D1A363F"
        desc = "YARA rule to look for an possible Rclone config file during incident response"
        date = "2026/01/08"
    strings:
        $rclone = "type = mega" nocase
        $s3 = "type = s3" nocase
    condition:
        filesize < 9KB and
        all of them
}
