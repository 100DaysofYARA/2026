import "lnk"

rule ta_rainbow_hyena_downloader_lnk
{
    meta:
        description = "Detects Rainbow Hyena (Head Mare, PhantomCore) LNK downloader used to deliver the PhantomRemotePS backdoor"
        author = "@t3ft3lb"
        date = "2026-01-27"
        reference = "https://habr.com/ru/companies/F6/articles/987734/"
        hash1 = "15d5e71ce278bb21842ac64b7a654b61832e3703fddb1307a8a2ea9ab1da60c0"
        hash2 = "bd149347be4141752dc206f833c6410ef065bfa9353cb370c543fa58dfc27f60"

    condition:
        uint32(0) == 0x0000004C and uint32(4) == 0x00021401 and
        filesize > 1KB and filesize < 3KB and
        (
            lnk.tracker_data.machine_id == "desktop-i2gatfr" or
            (
                lnk.cmd_line_args contains "delims=s\\\"" and
                lnk.cmd_line_args contains "('set^|findstr" and
                lnk.cmd_line_args contains "do cmd /c for /f \"tokens=*\"" and
                lnk.cmd_line_args contains "New-Object Net.WebClient" and
                lnk.cmd_line_args contains "DownloadString" and
                lnk.cmd_line_args contains "-WindowStyle Hidden" and
                (
                    lnk.cmd_line_args contains "wp-includes" or
                    lnk.cmd_line_args contains "post-template.html"
                )
            )
        )  
}