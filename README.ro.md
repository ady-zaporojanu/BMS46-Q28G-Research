# BMS46 Q28G — proiect Ghidra pentru colaborare

Acest repository conține cercetarea pentru firmware-ul **01119700F000Q28G**:
756 de funcții, 4.523 de comentarii, 3.259 de etichete globale, structuri de date,
sursele extensiei CPU32 și instrumentele pentru reconstruirea proiectului.

Se bazează și pe munca comunității, inclusiv Bartek0x00/BMS46-Wiki. Nu revendicăm
autorul exclusiv al cercetării inițiale sau al extensiei Ghidra.

Repository-ul text este însoțit acum de **colecția completă de materiale**:
proiectul Ghidra original, gata de deschis, arhiva programului `.gzf`, BIN-uri
full/parțiale, definiții XDF/XML pentru TunerPro, map-pack-uri și cercetarea istorică.
[Deschide materialele din repository](materials/README.md) sau descarcă
[colecția completă din Releases](https://github.com/ady-zaporojanu/BMS46-Q28G-Research/releases/tag/v0.2.0). Vezi [MATERIALS.md](docs/MATERIALS.md);
licența codului nu se aplică automat firmware-urilor și documentelor terțe.

Pentru reconstruirea din repository-ul text, fiecare contributor folosește propria
copie de firmware; scripturile verifică dimensiunea și SHA-256.
Nu trebuie conectat cablul la mașină sau la banc pentru a lucra aici.

1. Citește [README în engleză](README.md) și [instrucțiunile de pornire](docs/QUICKSTART.md).
2. Rulează `python tools/validate.py` pentru verificările fără firmware.
3. Instalează extensia în Ghidra 12.1.2 și construiește un proiect nou.
4. Lucrează într-un branch; schimbările se trimit prin pull request, în fișiere text.

Testele ventilatorului acoperă 74.049 de cazuri în simulare limitată. Nu reprezintă
o validare electrică pe ECU. Funcțiile necunoscute și unitățile nemăsurate sunt
păstrate ca atare; numărul de funcții denumite nu înseamnă procent de firmware descifrat.

În importul din fișiere text, semnăturile și variabilele locale sunt doar referință.
**Proiectul complet `.gzf` le păstrează**, inclusiv toate cele 23 de semnături
definite manual. Detalii: [reconstrucție](docs/RECONSTRUCTION.md).

BIN-urile full și parțiale, definițiile și programul Ghidra `.gzf` sunt în `materials/`.
Arhiva din Releases include și proiectul `.gpr` împreună cu baza `.rep` și istoricul cercetării.
