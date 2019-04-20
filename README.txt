Scriptul este scris in python 2.7 si poate fi folosit pentru analiza statica a executabilelor de tip PE sau Mach-O.

Pentru rulare este nevoie de modulele de python 2.7 si de librariile pefile, macholib, magic.

Instalarea modulelor necesare se poate face folosind comenzile:
$pip install pefile 
$pip install filemagic
$pip install macholib


Pentru o analiza rapida si eficienta modulele pefile si macholib pun la dispozitie
clasele pentru crearea unei imagini a exeutabilul in memorie cu ajutorul carora putem usor
afisa sectiunile acestora , putem calcula entropia fiecarei sectiuni respectiv sa verificam
diferite simboluri , importate sau folosite de executabilele analizate.

Proiectul isi propune un scurt studiu al naturii binarelor si verificarea daca acesta
a fost impachetat cu un utilitar cunoscut  (e.g. UPX sau MPRESS) folosind teste bazate pe entropie
care masoara gradul de imprastiere al octetilor in cadrul binarul.Analizorul cauta dupa semnatura 
celor 2 utilitare cunoscute , in cazul in care acestea nu se gasesc sectiunea e marcata ca find
comprimata cu un utilitar inca necunoscut.

Functie de entropie este calculata astfel: H(x) = sum (-p(x) * log2(p(x)) ) , unde p(x) este probabilitate
de aparitie a byte-ului x in cadrul sectiunii respective.
Evident avand la dispozitie 256 de valori posibile (0-255) , valoarea entropiei va fi situata intre 0 si 8.

Conform unui studiilor facute o sectiune comprimata sau criptata are o entropie in medie mai mare ca 6.8.
Analizor cand va detecta o entropie peste aceasta valoare va cauta dupa o semnatura cunoscuta.

References:
https://www.researchgate.net/profile/Heejo_Lee/publication/224204820_Generic_unpacking_using_entropy_analysis/links/5590a78e08ae1e1f9bae24b9/Generic-unpacking-using-entropy-analysis.pdf
https://nnt.es/Using%20Entropy%20Analysis%20to%20Find%20Encrypted%20and%20Packed%20Malware.pdf


 

