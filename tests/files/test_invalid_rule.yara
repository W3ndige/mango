rule InvalidRule {
    strings:
        $a = "foo"
    condition:
        $b
}
