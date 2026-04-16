import "console"
import "pe"

rule HELPER_get_pe_cert_info
{
    meta:
        description = "Extracts digital signature metadata from PE file certificates. NOTE: For better output, run in a single thread."
        author = "@t3ft3lb"
        date = "2026-03-03"

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and
        for any sig in pe.signatures : (
            console.log("=== Certificate ===") and
            console.log("issuer: ", sig.issuer) and
            console.log("subject: ", sig.subject) and
            console.log("thumbprint: ", sig.thumbprint) and
            console.log("version: ", sig.version) and
            console.log("algorithm: ", sig.algorithm) and
            console.log("algorithm_oid: ", sig.algorithm_oid) and
            console.log("serial: ", sig.serial) and
            console.log("not_before: ", sig.not_before) and
            console.log("not_after: ", sig.not_after) and
            console.log("=== CounterSignature ===") and
            console.log("verified: ", sig.verified) and
            console.log("digest: ", sig.digest) and
            console.log("digest_alg: ", sig.digest_alg)
        )
}