rule obfusheader_obfuscator_strings : malware {
    meta:
        name        = "obfusheader_strings"
        category    = "anti-analysis"
        description = "This YARA rule detects hardcoded strings in binaries obfuscated using obfusheader (https://github.com/ac3ss0r/obfusheader.h). "
        author      = "SquiblydooBlog"
        created     = "2026-01-03"
        reliability = 100
        tlp         = "TLP:clear"
        sample      = "3465a3d71c3187038ed73ebb89f899e3c6290841c152086c910ea54e54918c55"

    strings:
        $ = "Reconsider your life choices"
        $ = "Stop reversing the binary"
        $ = "And go touch some grass"

    condition:
        all of them
}
