#!/bin/zsh
rm -f wordlist.txt
for char in '%20' '%0a' '%00' '%0d0a' '.' '..'; do
    for ext in '.php' '.phar' '.pgif'; do
        echo "cmd$char$ext.gif" >> wordlist.txt
        echo "cmd$ext$char.gif" >> wordlist.txt
        echo "cmd.gif$char$ext" >> wordlist.txt
        echo "cmd.gif$ext$char" >> wordlist.txt
    done
done