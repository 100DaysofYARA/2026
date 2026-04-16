import "pe"

rule nsis_installer : tool {
    meta:
        name        = "nsis pe section"
		category  	= "packer"
        description = "Detects NSIS files based on the ndata PE section."
        author      = "SquiblydooBlog"
        created     = "2026-01-15"
        reliability = 100
        tlp         = "TLP:clear"
        sample      = "5626a3ac004ec2b1e075fa74e25188d7e30438b089b79bf93774fa1a3dd1dbfe"
		reference   = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"

    condition:
        uint16(0) == 0x5a4d and pe.sections[3].name == ".ndata"
}