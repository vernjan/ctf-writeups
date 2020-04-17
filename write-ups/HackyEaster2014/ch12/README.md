# 12 - Number Cracker

Easter bunny has placed an easter egg on the server. You need to crack a number, in order to get it.

Connect to **port 7701** using netcat or similar:

`nc he-archive.sieber.space 7701`

Submit your guess for the number, and analyze the reply, which will give you a hint.

Once you submit the right number, you'll get the egg.

![](number_cracker.jpg)

---

This is how the guessing works:
```
$ nc he-archive.sieber.space 7701
Enter your guess, dude:
100
I need 20 digits, dude!
$ nc he-archive.sieber.space 7701
Enter your guess, dude:
10000000000000000000
0<
```

This mean the digit on the 1st position is smaller than expected.

```
$ nc he-archive.sieber.space 7701
Enter your guess, dude:
20000000000000000000
1<
```

Okay, no we have guessed the first digit correctly. 19 digits to go.

To save manual work, I wrote a simple Bash script:
```shell script
#!/usr/bin/env bash

guess=00000000000000000000

while true; do
  echo "Guessing $guess"
  guess_result=$(echo $guess | nc he-archive.sieber.space 7701 | tail -n +2) # Skip 1st line

  if [[ $guess_result =~ ^[0-9]+.$ ]]; then
    echo "$guess_result"
    digit_index=${guess_result:0:-1}
    guess=$(bc <<<"$guess + 10 ^ (19 - $digit_index)")
  else
    # Grab 4th line and decode
    echo "$guess_result" | sed -n '4p' | base64 -di > egg12.png
    xdg-open egg12.png
    exit 0
  fi

  sleep 0.1
done
```

The correct number is `28232920712967180259`

Here is the egg:

![](egg12.png)
