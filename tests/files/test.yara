rule Text {
    strings:
        $text = "foo"
    condition:
        $text
}
