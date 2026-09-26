// YARA throughput case: one plain text string (bench/scripts/refbench.sh).
rule single_text
{
    strings:
        $a = "Microsoft"
    condition:
        $a
}
