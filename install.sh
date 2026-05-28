#!/bin/bash

clear

echo "EASETUP TOOLS"

sleep 1

while true; do

clear

echo "1. Test"
echo "2. Exit"
echo ""

read -p "Select: " menu

case $menu in

1)
echo "WORKING"
sleep 2
;;

2)
exit
;;

*)
echo "Invalid"
sleep 1
;;

esac

done
