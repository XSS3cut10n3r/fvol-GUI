// YARA throughput case: hex strings (wildcards, nibbles, jumps, alternatives) + regex strings.
rule pe_headers
{
    strings:
        $mz = { 4D 5A 90 00 03 00 00 00 04 00 }
        $pe = { 50 45 00 00 ( 4C 01 | 64 86 ) }
        $dos = { 54 68 69 73 20 70 72 6F 67 72 61 6D [4-12] 44 4F 53 }
    condition:
        any of them
}

rule code_patterns
{
    strings:
        $syscall = { 4C 8B D1 B8 ?? ?? 00 00 }
        $prolog = { 48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? }
        $nibble = { 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8? C0 }
        $jumpy = { 48 8B 05 ?? ?? ?? ?? [2-6] FF 15 }
        $alt = { FF 15 ?? ?? ?? ?? ( 85 C0 | 48 85 C0 | 3B C3 ) 7? }
    condition:
        any of them
}

rule regex_strings
{
    strings:
        $url = /https?:\/\/[a-zA-Z0-9.\/?=_%:-]{4,64}/
        $ip = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/
        $exe = /[a-z0-9_]{3,16}\.(exe|dll|sys)/ nocase
        $dev = /\\Device\\HarddiskVolume\d{1,2}/
    condition:
        any of them
}
