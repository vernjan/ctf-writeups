<?php

$alphabet = "abcdefghijkmpqrstuvwxyzABCDEFGHJKLMPQRSTUVWXYZ23456789";

for ($i = 0; $i < 0x100000000; $i++) {

    // seed
    srand($i);

    $password = '';

    for ($j = 0; $j < 12; $j++) {
        $rand_number = rand(0, 53);
        $password .= $alphabet[$rand_number];
    }

    echo $password . "\n";

}

echo "Sorry :/";
exit(1);