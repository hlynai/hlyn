#!/bin/sh
# A leaf whose issuer URLs point at listen.py on 127.0.0.1:47010. Checking it
# makes trustd fetch those URLs, which is how FINDINGS.md's trustd route was shown.
set -e; cd "$(dirname "$0")"; O=${OPENSSL:-openssl}
$O req -x509 -newkey rsa:2048 -nodes -keyout root.key -out root.pem -days 30 -subj "/CN=hlyn test root" -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" 2>/dev/null
$O req -newkey rsa:2048 -nodes -keyout int.key -out int.csr -subj "/CN=hlyn test intermediate" 2>/dev/null
printf "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign\n" > int.ext
$O x509 -req -in int.csr -CA root.pem -CAkey root.key -CAcreateserial -out int.pem -days 30 -extfile int.ext 2>/dev/null
$O req -newkey rsa:2048 -nodes -keyout leaf.key -out leaf.csr -subj "/CN=leak.example" 2>/dev/null
printf "subjectAltName=DNS:leak.example\nauthorityInfoAccess=caIssuers;URI:http://127.0.0.1:47010/SECRET-via-trustd-caIssuers.cer\nextendedKeyUsage=serverAuth\n" > leaf.ext
$O x509 -req -in leaf.csr -CA int.pem -CAkey int.key -CAcreateserial -out leaf.pem -days 30 -extfile leaf.ext 2>/dev/null
echo "wrote leaf.pem"
