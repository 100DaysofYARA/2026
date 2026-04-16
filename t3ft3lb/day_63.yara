import "pe"

rule tool_screenconnect_windowsclient
{
    meta:
        description = "Detects the Windows client of ScreenConnect (ConnectWise Control) RMM software"
        author = "@t3ft3lb"
        date = "2026-03-04"
        reference = "https://www.screenconnect.com/"
        hash1 = "3b150443fbb196446479367dc44888488045ae8eef9b872406656cf33ace2556"
        hash2 = "139bbbece5a67b207d658f3de10b89b648d8d656b3a2e444e8591c0c5d390bcf"
        hash3 = "b80d07610b81bddb3d7f30a207a2e134b559e06b8440598a926f3a9c1d439218"

    strings:
        $x = "ScreenConnect" ascii fullword
        
        $s0 = "RunFileElevated" wide fullword
        $s1 = "TaskbarCreated" wide fullword
        $s2 = "ClientService" wide fullword
        $s3 = "WindowsClient" wide fullword
        $s4 = "EndPointManager" wide fullword
        $s5 = "Must specify client launch parameters as argument or from ClickOnce context" wide fullword

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and
        filesize > 400KB and filesize < 1MB and
        #x > 10 and 4 of ($s*) and
        for any sig in pe.signatures : (
            sig.subject icontains "ConnectWise"
        )
}