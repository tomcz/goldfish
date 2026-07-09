#!/usr/bin/env bash
set -u

expected="$1"
version_url="${BASE_URL}/version"

echo "Checking $version_url"
for i in {1..10}; do
  if [[ "$i" -gt "1" ]]; then
    echo "Sleeping..."
    sleep 10
  fi
  actual=$(curl -s "$version_url")
  echo "Expected: $expected"
  echo "Actual:   $actual"
  if [[ "$expected" == "$actual" ]]; then
    echo 'OK'
    exit 0
  fi
done
echo 'Failed!'
exit 1
