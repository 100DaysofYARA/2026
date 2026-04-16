import "dotnet"

rule ta_silent_werewolf_etdownloader
{
    meta:
        description = "Detects Silent Werewolf (XDSpy) ETDownloader"
        author = "@t3ft3lb"
        date = "2026-01-16"
        reference_1 = "https://bi.zone/eng/expertise/blog/silent-werewolf-ispolzuet-novye-zagruzchiki-v-atakakh-na-rossiyskie-i-moldavskie-organizatsii/"
        reference_2 = "https://harfanglab.io/insidethelab/sadfuture-xdspy-latest-evolution/"
        hash1 = "95060ba948948eea9bfc801731960b97d3efceb300622630afcbccfe12c21ccd"
        hash2 = "056cd36bf4bc6efc119a64f2ffedd76f3dcb75daa95c22c59d91664dfcaa6fd5"
        hash3 = "2ec02422fcb2085b7ddbaefb805368bcbeaad66c2e41791391ad629ef6932ba5"

    strings:
        $s0 = "MyClass" ascii fullword
        $s1 = "ExportTests.dll" ascii fullword
        $s2 = "set_UseShellExecute" ascii fullword
        $s3 = "$fcca44e8-9635-4cd7-974b-e86e6bce12cd" ascii fullword

        /*
        0x000B509E 14           IL_00CA: ldnull
        0x000B509F 1304         IL_00CB: stloc.s   V_4
        0x000B50A1 09           IL_00CD: ldloc.3
        0x000B50A2 2813000006   IL_00CE: call      string ExportTests.MyClass::IbmlluFjkoivdrNBoQxMsZNVimQtVMkiuajWIaFug(string)
        0x000B50A7 280800000A   IL_00D3: call      uint8[] [mscorlib]System.Convert::FromBase64String(string)
        0x000B50AC 1304         IL_00D8: stloc.s   V_4
        0x000B50AE 1F1A         IL_00DA: ldc.i4.s  26
        0x000B50B0 281200000A   IL_00DC: call      string [mscorlib]System.Environment::GetFolderPath(valuetype [mscorlib]System.Environment/SpecialFolder)
        0x000B50B5 7E06000004   IL_00E1: ldsfld    string ExportTests.MyClass::vyZYzbwWUUxJNmwuJXgfpLsgWoyCrshvLTdvEejOJ
        0x000B50BA 2813000006   IL_00E6: call      string ExportTests.MyClass::IbmlluFjkoivdrNBoQxMsZNVimQtVMkiuajWIaFug(string)
        */
        $h0 = { 14 13 04 09 28 ?? 00 00 06 28 ?? 00 00 0A 13 04 1F 1A 28 ?? 00 00 0A 7E ?? 00 00 04 28 }

        /*
        0x000B5123 1108         IL_014F: ldloc.s   V_8
        0x000B5125 18           IL_0151: ldc.i4.2
        0x000B5126 282700000A   IL_0152: call      class [mscorlib]System.IO.FileStream [mscorlib]System.IO.File::Open(string, valuetype [mscorlib]System.IO.FileMode)
        0x000B512B 732800000A   IL_0157: newobj    instance void [mscorlib]System.IO.BinaryWriter::.ctor(class [mscorlib]System.IO.Stream)
        0x000B5130 25           IL_015C: dup
        0x000B5131 6F2900000A   IL_015D: callvirt  instance void [mscorlib]System.IO.BinaryWriter::Flush()
        0x000B5136 25           IL_0162: dup
        0x000B5137 1104         IL_0163: ldloc.s   V_4
        0x000B5139 6F2A00000A   IL_0165: callvirt  instance void [mscorlib]System.IO.BinaryWriter::Write(uint8[])
        0x000B513E 6F2B00000A   IL_016A: callvirt  instance void [mscorlib]System.IO.BinaryWriter::Close()
        0x000B5143 17           IL_016F: ldc.i4.1
        0x000B5144 0B           IL_0170: stloc.1
        0x000B5145 DE1E         IL_0171: leave.s   IL_0191
        */
        $h1 = { 11 08 18 28 ?? 00 00 0A 73 ?? 00 00 0A 25 6F ?? 00 00 0A 25 11 04 6F ?? 00 00 0A 6F ?? 00 00 0A 17 0B DE 1E }

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and
        filesize > 30KB and filesize < 1MB and
        dotnet.is_dotnet and (dotnet.number_of_streams == 4 or dotnet.number_of_streams == 5) and
        3 of ($s*) and all of ($h*)
}