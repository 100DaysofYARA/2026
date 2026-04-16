rule susp_ta_translucent_werewolf_malicious_desktop_file
{
    meta:
        description = "Detects Translucent Werewolf (APT36) malicious desktop files"
        author = "@t3ft3lb"
        date = "2026-03-07"
        reference = "https://www.cloudsek.com/blog/investigation-report-apt36-malware-campaign-using-desktop-entry-files-and-google-drive-payload-delivery"
        hash1 = "a82b9aa03503f5c347d8932f509c37ff9872e51b9376c7d314e7bd7e453668fe"
        hash2 = "9943bdf1b2a37434054b14a1a56a8e67aaa6a8b733ca785017d3ed8c1173ac59"
        hash3 = "4c607f5e641810e940c93fef07de3c548773457fddde81bfc3b0d043ec60a6e6"

    strings:
        $s0 = "[Desktop Entry]" ascii fullword
        $s1 = "Exec=bash -c" ascii fullword
        $s2 = "&& chmod +x" ascii fullword
        $s3 = "Type=Application" ascii fullword
        $s4 = "Icon=application-pdf" ascii fullword

        $x0 = "https://drive.google.com" ascii fullword
        $x1 = "base64 -d)\"; eval" ascii fullword
        $x2 = "Name[en_IN]" ascii fullword
        $x3 = "$(date +%s)\";" ascii fullword

    condition:
        filesize > 300 and filesize < 2MB and
        all of ($s*) and any of ($x*)
}