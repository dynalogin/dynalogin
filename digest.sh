#!/bin/bash -x


HOTP_CODE="$1"

USER="tester1"
REALM="testr"
NONCE="0123456789"
METHOD=GET
URL=testlogin.php

HA1=`echo -n "${USER}:${REALM}:${HOTP_CODE}" | md5sum | cut -b1-32`

HA2=`echo -n "${METHOD}:${URL}" | md5sum | cut -b1-32`

RESPONSE=`echo -n "${HA1}:${NONCE}:${HA2}" | md5sum | cut -b1-32`

RESPONSE_SUFFIX="${NONCE}:${HA2}"

echo "user = $USER realm = $REALM suffix = $RESPONSE_SUFFIX"
echo "response = $RESPONSE"

