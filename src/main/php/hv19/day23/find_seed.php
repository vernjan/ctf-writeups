<?php

$alphabet1 = "23456789ABCDEFGHJKLMPQRSTUVWXYZabcdefghijkmpqrstuvwxyz";
$alphabet2 = "ABCDEFGHJKLMPQRSTUVWXYZ23456789abcdefghijkmpqrstuvwxyz";
$alphabet3 = "23456789abcdefghijkmpqrstuvwxyzABCDEFGHJKLMPQRSTUVWXYZ";
$alphabet4 = "abcdefghijkmpqrstuvwxyz23456789ABCDEFGHJKLMPQRSTUVWXYZ";
$alphabet5 = "abcdefghijkmpqrstuvwxyzABCDEFGHJKLMPQRSTUVWXYZ23456789";
$alphabet6 = "ABCDEFGHJKLMPQRSTUVWXYZabcdefghijkmpqrstuvwxyz23456789";

for ($i = 0; $i < 0x100000000; $i++) {

    // seed
    srand($i);

    if ($i % 10000000 == 0) {
        echo "$i\n";
    }

    $password1 = '';
    $password2 = '';
    $password3 = '';
    $password4 = '';
    $password5 = '';
    $password6 = '';

    for ($j = 0; $j < 12; $j++) {
        $rand_number = rand(0, 53);

        $password1 .= $alphabet1[$rand_number];
        $password2 .= $alphabet2[$rand_number];
        $password3 .= $alphabet3[$rand_number];
        $password4 .= $alphabet4[$rand_number];
        $password5 .= $alphabet5[$rand_number];
        $password6 .= $alphabet6[$rand_number];
    }

    check_password($password1, $alphabet1, $i);
    check_password($password2, $alphabet2, $i);
    check_password($password3, $alphabet3, $i);
    check_password($password4, $alphabet4, $i);
    check_password($password5, $alphabet5, $i);
    check_password($password6, $alphabet6, $i);
}

function check_password($password, $alphabet, $seed)
{
    if ($password == 'Kwmq3Sqmc5sA') {
        echo "YES: $password (seed: $seed, alphabet:$alphabet)";
        exit(0);
    }
}

echo "Sorry :/";
exit(1);