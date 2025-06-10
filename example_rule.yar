rule Suspicious_API_Calls
{
    strings:
        $a1 = "CreateRemoteThread"
        $a2 = "VirtualAllocEx"
        $a3 = "WriteProcessMemory"

    condition:
        any of them
}
