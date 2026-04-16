
rule apple_format_signature_detection : tool {
    meta:
        name        = "apple_signatures"
        category    = ""
        description = "This YARA rule detects hardcoded strings which are part of Apple code-signing."
        author      = "SquiblydooBlog"
        created     = "2026-01-05"
        reliability = 75
        tlp         = "TLP:clear"
        sample      = "7cfe0b119e616ac81ddb1767a5c7f40bec67d91fdd66e53490c0225789537073"

    strings:
        $ = "Reliance on this certificate by any party assumes acceptance of the then applicable standard terms and conditions of use, certificate policy and certification practice statements."
        $ = "Developer ID Certification Authority"
        $ = "Apple Timestamp Certification Authority"
        $ = "Developer ID Application:"

    condition:
        all of them
}