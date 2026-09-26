// YARA throughput case: one text string with nocase + wide + ascii (4-way atom expansion).
rule single_nocase_wide
{
    strings:
        $a = "password" nocase wide ascii
    condition:
        $a
}
