# Getting Started

1. Docker und VSCode installieren

2. In VSCode die Devcontainer extension installieren

3. Im root folder des directories VSCode oeffnen, hier sollte sich nun ein popup oeffnen das vorschlaegt den Devcontainer zu oeffnen. Falls nichts aufploppt `STRG + SHIFT + p -> Devcontainers: Reopen in Container`.

4. Erste Experimente mit dem polynomial masking Laola multiplication gadget kannst du testen mit: 
```bash
cd pytool 
python3 kai_experiments.py
``` 
Bei der progress bar nicht wundern die ist broken und zeigt tupel nicht an die mittels einer speziellen Optimierung verifiziert werden. Solange es am Ende nen Haken wirft ist richtig.

5. Ein grober overview der fuer dich relevanten Sachen:
    - `gadget.py`: Ein grober ueberblick ueber die generellen Funktionen die Gadgets implementieren.
    - `encoding.py`: Hier liegen alle encodings, i.e. implementierten maksing schemes. Von denen sind fuer dich wahrscheinlich nur AddEnc (die ist additives secret sharing, also die Oberklasse von Boolean masking) und PolyEnc (polynomielles masking, sowohl per shamir secret sharing fuer k=1 secret, als auch packed secret sharing fuer k>1) relevant. 
    - `isw_gadgets.py`: Enthaelt gadgets die sich an der ISW struktur orientieren um auf additiven sharings zu rechnen. Hier koenntest du ansetzen um das dependent multiplication gadget fuer additive sharing zu implementieren um dich etwas auszuprobieren.
    - `polymasking_gadgets.py`: Das hier ist knackig, da ist ne ganze Menge an polymasking gadgets drin, viele davon sind potenziell erstmal nicht relevant. Fuer dich ist vielleicht erstmal nur wichtig das `LaolaMultGadget` und `BGWMultGadget` beide Gegenstuecke zu dem `ISWMult` sind.
