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
