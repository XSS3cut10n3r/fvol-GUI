// YARA throughput case: 20 text strings in one rule (multi-atom search).
rule text20
{
    strings:
        $s01 = "kernel32"
        $s02 = "ntdll"
        $s03 = "svchost"
        $s04 = "explorer"
        $s05 = "lsass"
        $s06 = "winlogon"
        $s07 = "csrss"
        $s08 = "services"
        $s09 = "advapi32"
        $s10 = "user32"
        $s11 = "shell32"
        $s12 = "ole32"
        $s13 = "msvcrt"
        $s14 = "wininet"
        $s15 = "ws2_32"
        $s16 = "crypt32"
        $s17 = "rpcrt4"
        $s18 = "gdi32"
        $s19 = "comctl32"
        $s20 = "oleaut32"
    condition:
        any of them
}
