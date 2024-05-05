#!/bin/bash

# https://www.openssl.org/docs/man1.0.2/man1/enc.html

echo "foo bar" | openssl enc -des-ecb -K 6162636461626364 -a -provider legacy -provider default
echo "foo bar" | ./ft_ssl des-ecb -k 6162636461626364 -a
# YZF3QKaabXUwxNg3obhMfw==

echo "foo bar des-ecb decrypt" | openssl enc -des-ecb -K 6162636461626364 -a -provider legacy -provider default | ./ft_ssl des-ecb -k 6162636461626364 -a -d
echo "foo bar des-ecb encrypt" | ./ft_ssl des-ecb -k 6162636461626364 -a | openssl enc -des-ecb -K 6162636461626364 -a -provider legacy -provider default -d

echo "foo bar des3-ecb decrypt" | openssl enc -des-ede3-ecb -K 6162636461626364 -a -provider legacy -provider default | ./ft_ssl des3-ecb -k 6162636461626364 -a -d
echo "foo bar des3-ecb encrypt" | ./ft_ssl des3-ecb -k 6162636461626364 -a | openssl enc -des-ede3-ecb -K 6162636461626364 -a -provider legacy -provider default -d

echo "foo bar des-cbc decrypt" | openssl enc -des-cbc -K 6162636461626364 -iv aabbccddeeff -a -provider legacy -provider default | ./ft_ssl des-cbc -k 6162636461626364 -v aabbccddeeff -a -d
echo "foo bar des-cbc encrypt" | ./ft_ssl des-cbc -k 6162636461626364 -v aabbccddeeff -a | openssl enc -des-cbc -K 6162636461626364 -iv aabbccddeeff -a -provider legacy -provider default -d

echo "foo bar des3-cbc decrypt" | openssl enc -des-ede3-cbc -K 6162636461626364 -iv aabbccddeeff -a -provider legacy -provider default | ./ft_ssl des3-cbc -k 6162636461626364 -v aabbccddeeff -a -d
echo "foo bar des3-cbc encrypt" | ./ft_ssl des3-cbc -k 6162636461626364 -v aabbccddeeff -a | openssl enc -des-ede3-cbc -K 6162636461626364 -iv aabbccddeeff -a -provider legacy -provider default -d

echo "foo bar des-pcbc ecrypt decrypt" | ./ft_ssl des-pcbc -k 6162636461626364 -v aabbccddeeff -a | ./ft_ssl des-pcbc -k 6162636461626364 -v aabbccddeeff -a -d
echo "foo bar des3-pcbc ecrypt decrypt" | ./ft_ssl des3-pcbc -k 6162636461626364 -v aabbccddeeff -a | ./ft_ssl des3-pcbc -k 6162636461626364 -v aabbccddeeff -a -d

echo "foo bar des-ctr ecrypt decrypt" | ./ft_ssl des-ctr -k 6162636461626364 -v aabbccddeeff -a | ./ft_ssl des-ctr -k 6162636461626364 -v aabbccddeeff -a -d
echo "foo bar des3-ctr ecrypt decrypt" | ./ft_ssl des3-ctr -k 6162636461626364 -v aabbccddeeff -a | ./ft_ssl des3-ctr -k 6162636461626364 -v aabbccddeeff -a -d

echo "foo bar des-cfb decrypt" | openssl enc -des-cfb -K 6162636461626364 -iv aabbccddeeff -a -provider legacy -provider default | ./ft_ssl des-cfb -k 6162636461626364 -v aabbccddeeff -a -d
echo "foo bar des-cfb encrypt" | ./ft_ssl des-cfb -k 6162636461626364 -v aabbccddeeff -a | openssl enc -des-cfb -K 6162636461626364 -iv aabbccddeeff -a -provider legacy -provider default -d

echo "foo bar des3-cfb decrypt" | openssl enc -des-ede3-cfb -K 6162636461626364 -iv aabbccddeeff -a -provider legacy -provider default | ./ft_ssl des3-cfb -k 6162636461626364 -v aabbccddeeff -a -d
echo "foo bar des3-cfb encrypt" | ./ft_ssl des3-cfb -k 6162636461626364 -v aabbccddeeff -a | openssl enc -des-ede3-cfb -K 6162636461626364 -iv aabbccddeeff -a -provider legacy -provider default -d

echo "foo bar des-ofb decrypt" | openssl enc -des-ofb -K 6162636461626364 -iv aabbccddeeff -a -provider legacy -provider default | ./ft_ssl des-ofb -k 6162636461626364 -v aabbccddeeff -a -d
echo "foo bar des-ofb encrypt" | ./ft_ssl des-ofb -k 6162636461626364 -v aabbccddeeff -a | openssl enc -des-ofb -K 6162636461626364 -iv aabbccddeeff -a -provider legacy -provider default -d

echo "foo bar des3-ofb decrypt" | openssl enc -des-ede3-ofb -K 6162636461626364 -iv aabbccddeeff -a -provider legacy -provider default | ./ft_ssl des3-ofb -k 6162636461626364 -v aabbccddeeff -a -d
echo "foo bar des3-ofb encrypt" | ./ft_ssl des3-ofb -k 6162636461626364 -v aabbccddeeff -a | openssl enc -des-ede3-ofb -K 6162636461626364 -iv aabbccddeeff -a -provider legacy -provider default -d
