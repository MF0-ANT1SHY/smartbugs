#!/bin/sh

FILENAME="$1"

cd /conkas
python3 conkas.py -vt time_manipulation "$FILENAME"
