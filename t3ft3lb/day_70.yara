rule ta_watch_wolf_rarsfx_dropper
{
    meta:
        description = "Detects Watch Wolf (Hive0117) RarSFX dropper distributing DarkWatchman RAT"
        author = "@t3ft3lb"
        date = "2026-03-11"
        reference = "https://cyble.com/blog/sophisticated-darkwatchman-rat-spreads-through-phishing-sites/"
        hash1 = "1586d4e502d7470cf9d40a8057503cdf3a22274bfadc4cfb8fb60a4d095b6601"
        hash2 = "c96ecdc1d1b001ca7113557e9a6c3fba9a085f755b7a8cf15ae2e8bdd293d68b"
        hash3 = "847a9300c2d9324a0851df6e9f4a10a103f185ba7fcb9bf61f6077a9ee0c1745"

    strings:
        $sfxrar = "sfxrar.pdb" ascii fullword

        $r0 = /Setup=[0-9]{7,12}\.js \"%sfxname%\"/ ascii fullword
        $r1 = /Setup=wscript\.exe [0-9]{7,12}\.js [0-9]{1,3} \"%sfxname%\"/ ascii fullword
        $r2 = /start \/MIN wscript\.exe \/E:jscript ([0-9]{7,12}|[0-9]{7,12}\.js) [0-9]{1,3} \"%sfxname%\"/ ascii fullword

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and
        filesize > 200KB and filesize < 700KB and
        $sfxrar and any of ($r*)
}