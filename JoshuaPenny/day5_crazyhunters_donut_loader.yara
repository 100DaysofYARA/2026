import "pe"
import "math"

rule CrazyHunters_Donut_Loader
{
    meta:
        desc = "Detects Donut Loader (bb.exe) used by Crazyhunters"
        author = "@josh_penny"
        hash = "2cc975fdb21f6dd20775aa52c7b3db6866c50761e22338b08ffc7f7748b2acaa"
        reference = "https://www.trellix.com/blogs/research/the-ghost-in-the-machine-crazyhunters-stealth-tactics/"
        date = "2026-01-08"
    strings:
        $pdb1 = "D:\\a\\_work\\1\\s\\artifacts\\obj\\coreclr\\windows.x64.Release\\dlls\\mscordac\\mscordaccore.pdb"
        $pdb2 = "D:\\a\\_work\\1\\s\\artifacts\\obj\\coreclr\\windows.x64.Release\\Corehost.Static\\singlefilehost.pdb"
        $pdb3 = "D:\\a\\_work\\1\\s\\src\\coreclr\\vm\\win32threadpool.cpp"
        $str = "hostpolicy.dll" wide
    condition:
        uint16(0) == 0x5A4D and all of ($pdb*) and $str and
        pe.imphash() == "a44edecd836f33aa8c9358508613cd5c" and
        pe.export_timestamp == 0xFFFFFFFF and
        pe.exports("DotNetRuntimeInfo") and
        and pe.overlay.offset != 0
        and pe.overlay.size > 10240
        and math.entropy(pe.overlay.offset, pe.overlay.size) >= 7.2 and
        filesize > 8MB and filesize < 15MB
}