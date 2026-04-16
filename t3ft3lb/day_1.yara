import "console"
import "hash"
import "pe"

rule HELPER_calc_hashes_and_size_pefile
{
    meta:
        description = "Calculates hashes and size for PE files (excluding .NET executables). NOTE: For better output, use a single thread."
        author = "@t3ft3lb"
        date = "2026-01-01"

    strings:
        $dotnet = ".NET Framework" ascii fullword

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and
        not $dotnet and
        console.log("MD5: ", hash.md5(0, filesize)) and
        console.log("SHA-1: ", hash.sha1(0, filesize)) and
        console.log("SHA-256: ", hash.sha256(0, filesize)) and
        console.log("imphash: ", pe.imphash()) and
        console.log("filesize (bytes): ", filesize)
}