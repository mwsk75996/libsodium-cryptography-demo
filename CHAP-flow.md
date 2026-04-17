# CHAP transaktion flow

Dette er det design som `chap_demo`, `mqtt_chap_server` og `mqtt_chap_client` implementerer.

## De 4 packets

1. Client -> server: klienten sender login request med brugernavn.
2. Server -> client: serveren genererer en tilfældig challenge/salt og sender den tilbage.
3. Client -> server: klienten beregner en response hash/MAC ud fra challenge og den delte hemmelighed.
4. Server -> client: serveren beregner samme response lokalt og svarer `OK` eller `AFVIST`.

## Hvorfor det er bedre end PAP

PAP sender typisk brugernavn og password direkte til serveren. CHAP sender ikke selve passwordet over forbindelsen. I stedet beviser klienten at den kender hemmeligheden ved at beregne korrekt response på serverens challenge.

## Vigtig begrænsning

Hvis den samme response kunne genbruges, ville en angriber kunne lave replay attack. Derfor skal serveren generere en ny tilfældig challenge for hvert login-forsøg, og gamle challenges skal slettes efter brug.
