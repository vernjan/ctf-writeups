#!/bin/bash

cat ips.txt | while read ip
do 
  http_code=$(curl -s -o /dev/null -w "%{http_code}\n" --proxy http://78.128.216.8:3128 http://$ip/)
  if [ $http_code -ne 403 ]; then
       echo "$ip: $http_code"
  fi
done