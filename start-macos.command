#!/bin/sh
cd "$(dirname "$0")" || exit 1
caffeinate -i ./FileShare
printf '\nPress Enter to close...'
read -r answer
