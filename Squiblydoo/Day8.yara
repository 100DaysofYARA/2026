import "math"

rule inflated_PE_file : suspect {
    meta:
        name        = "inflated_PE_file"
        category    = "evasion"
        description = "This detects on files greater than 300MB in size with a low entropy (low randomness). Average PE entropy is around 6 or 7. The files we are looking for are between 3 and 0.01."
        author      = "SquiblydooBlog"
        created     = "2026-01-08"
        reliability = 70
        tlp         = "TLP:clear"
        sample      = "e4598c7dc0adfa33b9140a385eab0350046c5b3433c0da676a5510803b9285c4"

    condition:
		uint16(0) == 0x5a4d and
		filesize > 300MB and
        math.entropy(0, filesize) < 3
}
