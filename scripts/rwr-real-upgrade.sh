#!/usr/bin/bash
set -o pipefail

printf "\n=== RWR PACKAGE INTELLIGENCE ===\n"
printf "ARCH LINUX — FULL SYSTEM UPGRADE\n\n"

/usr/bin/pkexec /usr/bin/pacman -Syu
result=$?

printf "\n=== WYNIK AKTUALIZACJI ===\n"
printf "Kod zakonczenia: %s\n" "$result"

if [ "$result" -eq 0 ]; then
    printf "AKTUALIZACJA ZAKONCZONA POMYSLNIE\n"
else
    printf "AKTUALIZACJA NIE ZAKONCZYLA SIE POMYSLNIE\n"
fi

printf "\nNacisnij ENTER, aby zamknac terminal...\n"
read -r _
exit "$result"
