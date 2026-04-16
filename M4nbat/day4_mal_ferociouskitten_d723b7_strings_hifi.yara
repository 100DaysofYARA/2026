rule mal_ferociouskitten_d723b7_strings_hifi {
    meta:
        author = "m4nbt"
        sha256 = "D723B7C150427A83D8A08DC613F68675690FA0F5B10287B078F7E8D50D1A363F"
        desc = "Unique strings from a sample of malware associated with the threat actor Ferocious Kitten."
        date = "2026/01/04"
    strings:
        $h1 = "\\mklg -binder\\Release"
        $h2 = "mklg-binder.pdb"
        $h3 = "/i.php?u=&i=proxy ip"
        $h4 = "bitsadmin /cancel pdj"
        $h5 = "bitsadmin /create pdj"
        $h6 = "bitsadmin /SetPriority pdj HIGH"
        $h7 = "bitsadmin /addfile pdj"
        $h8 = "bitsadmin /resume pdj"
        $s9 = "<mark>Hello: %s</mark>"
        $s10 = "svehost.exe"
    condition:
        uint16be(0) == 0x4d5a and
        90% of them
}
