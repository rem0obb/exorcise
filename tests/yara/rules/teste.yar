rule test 
{
strings:
    $test = ".bss"
    $test2 = ".text"
condition:
    $test2 and $test


}