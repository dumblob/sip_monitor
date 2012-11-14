% WTF?
% Jan Pacner
% 2012-10-13 12:54:17 CEST

\clearpage

moje prvni kapitola
===================

dokumentaci (soubor manual.pdf), která bude obsahovat uvedení do problematiky, návrhu aplikace, popis implementace, základní informace o programu, návod na použití. V dokumentaci se očekává následující: titulní strana, obsah, logické strukturování textu, přehled nastudovaných informací z literatury, popis zajímavějších pasáží implementace, použití vytvořených programů a literatura.

    `nejaky verbatim?`

    a co treba uvozovky "nazdarek"

Co není v zadání jednoznačně uvedeno, můžete implementovat podle svého vlastního výběru. Zvolené řešení popište v dokumentaci.

Jelikoz SIP je ciste textovy protokol obsahujici i zajisteni spolehlivosti, muze byt pouzit s kterymkoliv dostupnym protokolem schopnym prenaset data. Proto byla vybrana a implementovana podpora pouze pro ethernet, protokol IPv4/IPv6 a nad nim TCP a UDP. Ostatni typy paketu jsou tise zahazovany. Dale u\ IP, TCP ani UDP hlavicek neni kontrolovana spravnost obsahu (napr. minimalni velikost apod.). Fragmentace na IP vrstve neni podporovana a fragmentovane pakety jsou zahazovane (nepredpoklada se zasilani velkych paketu skrze SIP).

Kaslu na accept-encoding, na fragmentaci, na maximalni velikost zpravy (ctu pouze to, co se vejde do 1 paketu), na pocitani kontrolniho souctu IPv4, TCP a UDP (takze vubec neresim zachazeni s pseudo hlavickami), na IP-in-IP, na jumbogramy v IPv6, na utf-8, na chybove stavy SIP atd..

Co se provozu tyce, tak zezacatku se musi vterinku pockat nez se naplni okno, ktere pouziva libpcap - az pote zacne libpcap volat nasi obsluznou funkci.

Ukoncuji pomoci 3 signalu...

Zachycuji napr. pouze BYE a uz me nezajima potvrzeni OK, protoze pri BYE je stejne jiz klient "odpojeny"

Moje posledni kapitola
======================

Tak nevim, ale tohle by melo fungovat.

Pouzita literatura
==================

#. RFC
#. ta knizka, kterou nam doporucil Matousek na prednasce
#. Neco dalsiho?
