#!/bin/bash

binaries=(
    "inkmail"
    "inkmaild"
)

for file in "${binaries[@]}"; do
    if [[ ! -f "$file" ]]; then
        echo "Error: Required file '$file' is missing. Exiting..." >&2
        exit 1
    fi
done

echo "Built binaries found."

ftr pack . -C inkmail
ftr up inkmail*.sqar JFtR/inkmail
rm inkmail*.sqar
ftr pack . -U inkmail
ftr up inkmail*.fsdl JFtR/inkmail
rm inkmail*.fsdl

ftr query JFtR/inkmail
