% Monitor SIP hovorů
% Jan Pacner
% 2012-10-13 12:54:17 CEST

\clearpage

Úvod
====

Práce se zaměřuje na zpracování zpráv protokolu SIP a demonstruje některé z\ jeho možností skrze vytvořenou aplikaci. Důraz byl kladen na zpracování síťových paketů, zpráv prokolu SIP a na možnost multiplatformního použití výsledné aplikace. Veškerá funkcionalita byla implementována podle vhodných standardů. Protokol SIP slouží jako signalizace pro transportní multimediální síťové protokoly a nachází využití jak v\ prostředích s garantovanou spolehlivostí přenosu, tak i\ v\ prostředích bez ní.

Protokol SIP
============

Session Initiation Protocol je textový síťový protokol na aplikační vrstvě ISO/OSI modelu, sloužící k\ signalizaci pro multimediální transportní protokoly (RTP, RTCP apod.). Nejčastější využití nachází ve VoIP (Voice over IP), a to i\ přesto, že se dnes běžně v\ sítích setkáváme s\ implementací nesymtrického NAT, což způsobuje nepoužitelnost tohoto protokolu samostatně bez nasazení některého z\ mnoha způsobu `průchodů` skrze NAT zvnějšku (např. STUN). Specifikaci SIP lze nalézt v\ `RFC 3261`. Existuje mnoho rozšíření (např. pro zasílání IM textových zpráv, přenos dalších informací, upozorňování na události atd.) popsaných v\ dalších `RFC`.

Na síťové vrstvě jsou podporovány prokoly IP a IPv6. Na transportní vrstvě jsou podporovány protokoly TCP a UDP, avšak z\ principu funkčnosti lze použít i\ jakýkoliv jiný protokol umožňující přenášet blíže nespecifikovaná data. Pro SIP je vyhrazený port 5060.

Architektura SIP se skládá ze 2\ základních komponent. Jsou jimi UAS (User Agent Server) a UAC (User Agent Client). UAS udržuje databázi na něm zaregistrovaných uživatelů (metoda REGISTER) a směruje požadavky. UAC iniciuje a ukončuje pozadavky (metody INVITE, BYE, ACK, CANCEL, OPTION).

Adresování je prováděno pomocí SIP nebo SIPS URI (Uniform Resource Locator). Jako `scheme` se používá `sip` nebo `sips` v\ závislosti na tom, zdali se jedná o\ nešifrovaný nebo šifrovaný přenos. Varianta pro nešifrovaný přenos má tvar `sip:bob@biloxi.com` a varianta pro šifrovaný přenos `sips:bob@biloxi.com`. Tímto URI však nelze specifikovat konkrétní port na cílové stanici. Podporované je i\ směrování hovorů mezi UAS, čímž je zajištěna decentralizace celosvětové SIP architektury.

Podpora šifrování je zajištěna skrze transportní a síťovou vrstu za použití TLS a IPSec. Namísto SIP URI je poté použito SIPS URI. Bezpečnost transakcí mezi UASs je zaručena více způsoby a v\ `RFC 3261` jsou popsány všechny známé metody útoků spolu s\ doporučeními jak jim předejít (od podvržené registrace u\ brány až po DoS útoky). Bezpečnostní model je do značné míry odvozený z\ HTTP a SMTP.

Jednoduchý případ užití pro hovor inciovaný uzivatelem A, přijatý uživatelem B a ukončený uživatelem B by mohl vypadat následovně:

> ~~~~~~~~~~~~~~
A: INVITE
B: response (`status`, který potvrdí přijetí)
B: BYE
~~~~~~~~~~~~~~

Detailnější informace viz. implementace aplikace.

Návrh aplikace
==============

Program pracuje v\ promiskuitním módu na zvoleném síťovém rozhraní (nehledě na typ, zdali jde o\ drátové nebo bezdrátové připojení), což způsobí, že rámce přijaté síťovou kartou na ní nejsou zpracovány (tzn. není odstraněna hlavička ani kontrolní součet) a jsou v\ tomto `surovém` tvaru předány CPU. Pro předzpracování a čtení těchto PDU (Protocol Data Unit) byla zvolena knihovna libpcap, která je multiplatformní a projekt tedy lze přeložit na různých platformách. Předzpracování spočívá v\ odstranění kontorlního součtu a filtraci. Pomocí ní jsou vychytávány pouze PDU odpovídající protokolu IPv4 nebo IPv6 obsahující TCP nebo UDP hlavičku a z\ nich pouze ty, které uvádějí číslo portu 5060. Tím práce libpcap končí.

Nadále jsou zpracovány hlavičky všech přítomných protokolů (ethernet, IPv4, IPv6, TCP a UDP). Tyto jsou odstraněny a následuje zpracování zprávy SIP. Nejprve je zohledněn fakt, že SIP používá pro ukončování řádků CRLF a že řádky začínající prázdným znakem SP (mezena) nebo HTAB (horizontální tabulátor) značí pokračování předchozího řádu. Znaky CR jsou tedy odstraněny a `pokračující` řádky jsou spojeny s\ předchozím.

Z\ prvního řádku přijatých dat je poté zjištěno, zdali se skutečně jedná o\ protokol SIP a pokud ano, jsou ze zprávy vypreparovány informace jako její typ, argumenty (např. návratový kód, chybové hlášení v\ lidsky čitelné podobě, identifikace příslušné relace/sezení, odesílatel, příjemce apod.). V\ případě zahájení sezení metodou INVTE se zkontroluje přítomnost daných SIP/SIPS URI v\ seznamu povolených adres a pokud byl nalezen, jsou přidány stěžejní informace o\ novém hovoru do seznamu hovorů (pokud seznam nebyl při spuštění aplikace specifikován uživatelem, do seznamu hovorů je přidaný kterýkoliv nový hovor).

Při přijetí zprávy s\ metodou BYE jsou vypsány informace o\ právě dokončeném hovoru a odstraněn záznam ze seznamu hovorů.

Zpráva s\ metodou CANCEL znamená zrušení požadavku INVITE a zasílá ji ten, který zaslal první INVITE. Aplikace na to reaguje tak, že se přesune zpět do fáze „po INVITE“.

Po přijetí zprávy `response`, která potvrzuje přijetí hovoru nebo naopak indikuje chybu jsou vypsány informace o\ zahájení hovoru spolu s\ uložením časového razítka o\ započetí hovoru k\ položce v\ seznamu a v\ opačném případě je vypsána informace o\ odmítnutí hovoru.

Ostatní metody (ACK, REGISTER, atd. včetně rozšiřujících) nejsou využívány a jsou tedy tiše ignorovány. Např. metoda `ACK` je používána pro projcestný hand-shake mezi koncovými stanicemi (`caller` a `callee`) pro zajištění spolehlivého přenosu spolu s\ periodickým vysíláním požadavků. Problém však nenastává, protože v\ okamžiku, kdy stanice zahajující hovor metodou INVITE obdrží od protější stanice `response` s\ odpovědí 2xx, je tím hovor započatý. Toto tedy není chyba návrhu aplikace.

Implementace aplikace
=====================

K\ realizaci byl zvolen programovací jazyk\ C a knihovna libpcap. Při spuštění je nastaveno odchycení signálů SIGHUP, SIGTERM a SIGINT, přičemž všechny způsobí korektní uvolnění paměti a ukončení aplikace. Po zpracování argumentů (kde na argument `-u` je nahlíženo jako na dvojici argumentů `-t` a `-f`) je otevřeno zařízení knihovnou libpcap, následně je alokována paměť pro struktury na uchovávání zpracovaných informací z\ přijatých SIP zpráv a nakonec je spuštěna hlavní smyčka. V\ té se vyčítají do vyrovnávací paměti rámce z\ nastaveného síťového zařízení. Knihovna libpcap je vyfiltruje podle výše uvedeného filtru, přepočítá kontrolní součty a odstraní je a takto zpracovaná data předá fci odsraňující hlavičky jednotlivých protokolů.

Pro odstraňování hlaviček bylo připraveno několik struktur, reprezentující ethernetovou, IPv4, IPv6, TCP a UDP hlavičku. Podle příslušných standardů `RFC` je z\ hlaviček vyčítána velikost (u\ IPv4 je ještě kontrolována přítomnost příznaku Don't Fragment) a posouván ukazatel na začátek dat. Pro IPv6 hlavičku je samozřejmě podporované použití více hlaviček za sebou (pole `next header`). Nakonec je spočítána velikost zbývajících dat a spuštěna obslužná fce na zpracování zprávy SIP.

U\ hlaviček všech využívaných protokolů nejsou podporovány žádné kontrolní součty (není nutné tedy dělit data na pseudo hlavičky) ani není kontrolována správost obsahu (např. minimální velikost paketu). Dále nejsou podporovány následující fce uvedených protokolů:

*   fragmentace na IPv4 vrstvě (tyto pakety jsou zahazovány vyjma prvního fragmentu, protože je vysoká pravděpodobnost, že se nejdůležitější části SIP hlavičky vešly i\ do tohoto malého paketu)

*   maximální velikost SIP zprávy (pokud je zpráva rozdělena, zahazují se všechny pakety vyjma prvního, který obsahuje tu nejdůležitější hlavičku)

*   přenosy IP-in-IP

*   jumbogramy v\ IPv6

Data rozdělím na řádky a každý řádek zkouším zpracovávat několika regulárními výrazy. Pokud první řádek neodpovídá žádné metodě SIP z\ těch, které jsou nutné pro vyhodnocení stavu hovorů (tzn. INVITE, CANCEL, BYE a „status“), končím se zpracováním tohoto paketu.

V\ opačném případě testuji každý ze zbývajících řádků na přítomnost jedné z\ `message-header` dokud nejsou splněny podmínky pro danou skupinu několika `message-header` a nebo dokud nedočtu celý paket. Kontrola přítomnosti sounáležejících `message-header` je jediná implementovaná optimazilace. Další možností by bylo testovat před každým pokusem o\ porovnání s\ regulárním výrazem otestovat, zdali se s\ ním již jednou neporovnávalo a nebyl to úspěch. Výkonnostní problémy se však neočekávají, a\ proto jsem tato optimalizace nebyla implementována.

Pokud regulární výraz odpovídá, jsou z\ daného řádku skrze dílčí části regulárního výrazu (submatches) vypreparovány důležité části, alokována paměť vhodné velikosti a tyto části do ní uloženy. Regulární výrazy byly sestaveny podle ABNF (Augmented Backus-Naur Form) dostupné přímo v\ `RFC 3621`.

Jakmile je ukončeno zpracovávání SIP zprávy, je vše potřebné k\ dispozici a následuje jednoduché zpracování logikou zohledňující argumenty a stav hovoru v\ seznamu hovorů.

*   Metoda INVITE

    V\ tomto je vytvořen nový záznam do seznamu hovorů. Případně je aktualizován již existující záznam (tzv. re-INVITE). Všechny ostatní případy vyžadují již existující záznam v\ seznamu hovorů, protože vyžadují nalezení položky v\ seznamu hovorů podle odpovídajicího Call-ID. Což je unikátní identifikátor pro každý hovor mezi danými stanicemi (pokaždé jiný - v\ `RFC 3621` je popsáno doporučení jako ho vytvořit).

*   Metoda CANCEL

    Má smysl pouze v\ případě, že je nalezený hovor ze seznamu hovorů ve stavu `INVITE`. Poté je vypsáno na výstup v\ rámci povoleného argumentu `-a`, že se jedná o\ prozvonění.

*   Odpověď (response)

    Může být zaslána na mnoho požadavků, ale aplikace zpracovává pouze odpovědi na INVITE. Odpověď vždy obsahuje `status` (trojmístné číslo) popisující výsledek operace na stanici odesílající odpověď. Podle toho je rozhodnuto a jsou zpracovány pouze stavy chybové (začínající jinou číslicí nežli 1 nebo 2) a stavy OK (začínající číslicí 2). Stavy s\ 1\ na začátku jsou pouze informativní a nemění „úmysl“ stanice zahajující hovor.

    Pro stavy 2xx je uložena informace o\ aktuálním času ve dvou formách. Čas z\ `realtime` hodin a čas `monotonic` z\ blíže nespecifikovaného zdroje. Čas `realtime` podléhá přechodům mezi časovými pásmy, různým časovým úpravám (např. démon NTP) a uživatelským změnám, a proto nelze použít pro měření času. Naproti tomu čas `monotonic` je neměnný v\ rámci jednoho spušténí operačního systému a tudíž se hodí pro měření času. Nakonec je vypsána informace o\ zahájení nového hovoru.

    Pro všechny chybové stavy je zřejmé, že cílová stanice nemá zájem nebo se s\ námi z\ nějakého důvodu nemůže spojit. Bližší informaci o\ důvodu připojuje na konec řádku s\ metodou `response`. V\ případě chyby 488 však přidá ještě podrobný popis chyby do `message-header` s\ názvem `Warning`. Tato chybová hlášení se uživateli vypíšou na výstup spolu s\ informací o\ odepření hovoru. Ze seznamu hovorů je tento odstraněn.

*   Metoda BYE

    Způsobí okamžité ukončení hovoru. A\ to i\ přesto, že protistrana neodpoví nebo odpoví se zpožděním. Na výstup se tedy vypíše, že je daný hovor ukončen. Je uvedena informace kdy byl hovor zahájen a nakonec je spočítán rozdíl mezi uloženou hodnotou času `monotonic` a aktuální hodnotou času `monotonic` a tento rozdíl přepočítán na lidsky přijatelné jednotky (roky, měsíce, dny, hodiny, minuty a vteřiny) a výsledek vypsán na výstup.


Použití programu a jeho výstupy
===============================

Program má následující anotaci (synopsis), která odpovídá zadání:

> `sip_monitor -i <rozhrani> [-a|-c] [-f <id>] [-t <id>] [-u <id>]`

Program je nutné spouštět s\ právy uživatele `root` (kvůli promiskuitnímu módu). Po spuštění krátkou dobu trvá, než se začnou vypisovat informace, protože se mezitím naplňuje vyrovnávací paměť knihovny libpcap. V\ případě chyby se program ukončí s\ chybovým kódem\ `1`.

Při testování na FreeBSD\ 8.1 bylo zjištěno, že dostupná verze knihovny libpcap (1.1.1) v\ některých případech nehlásí srozumitelná chybová hlášení v\ případě výskytu problému, kdežto na testovacím Linuxovém stroji (kernel 3.4.9) s\ libpcap 1.3.0 pro obdobný chybný vstup knihovna vrátila srozumitelné chybové hlášení.

Příklady spuštění
=================

Níže je uvedeno několik ukázkových výstupů včetně parametrů spuštění.

### Jednoduché spuštění

~~~~~~~~~~~~~~~~~~~~~
# ./sip_monitor -i eth0
new call [started on 17.11.2012 12:59:06]:
  caller: sip:406284@sip.odorik.cz (Johnny English)
  callee: sip:*081@sip.odorik.cz
end call [started on 17.11.2012 12:59:06]:
  caller: sip:406284@sip.odorik.cz (Johnny English)
  callee: sip:*081@sip.odorik.cz
  duration: 0 years 0 months 0 days 00:01:14
~~~~~~~~~~~~~~~~~~~~~

### Pouze informace o\ dokončených hovorech

~~~~~~~~~~~~~~~~~~~~~
# ./sip_monitor -c -i eth0
end call [started on 17.11.2012 at 13:02:04]:
  caller: sip:406284@sip.odorik.cz (Johnny English)
  callee: sip:*081@sip.odorik.cz
  duration: 0 years 0 months 0 days 00:00:04
~~~~~~~~~~~~~~~~~~~~~

### Pouze informace o\ dokončených hovorech z/na vybrané adresy

~~~~~~~~~~~~~~~~~~~~~
# ./sip_monitor -c -i eth0 -u sip:406284@sip.odorik.cz
end call [started on 17.11.2012 at 13:06:16]:
  caller: sip:406284@sip.odorik.cz (Johnny English)
  callee: sip:*081@sip.odorik.cz
  duration: 0 years 0 months 0 days 00:00:04
~~~~~~~~~~~~~~~~~~~~~

### Duplicitní parametr

~~~~~~~~~~~~~~~~~~~~~
# ./sip_monitor -c -i eth0 -u sip:406284@sip.odorik.cz -t sip:406284@sip.odorik.cz
end call [started on 17.11.2012 at 13:08:12]:
  caller: sip:406284@sip.odorik.cz (Johnny English)
  callee: sip:*081@sip.odorik.cz
  duration: 0 years 0 months 0 days 00:00:23
~~~~~~~~~~~~~~~~~~~~~

### Jen informace o\ dokončených hovorechy hovory pro vybraného příjemce

~~~~~~~~~~~~~~~~~~~~~
# ./sip_monitor -c -i eth0 -t sip:406284@sip.odorik.cz
~~~~~~~~~~~~~~~~~~~~~

Nic se nevypsalo, protože bylo voláno z\ adresy `sip:406284@sip.odorik.cz` na adresu `sip:*081@sip.odorik.cz`.

### Omezení na jedinou adresu volajícího

~~~~~~~~~~~~~~~~~~~~
# ./sip_monitor -i eth0 -f sip:406284@sip.odorik.cz
new call [started on 17.11.2012 at 13:36:56]:
  caller: sip:406284@sip.odorik.cz (Johnny English)
  callee: sip:*081@sip.odorik.cz
end call [started on 17.11.2012 at 13:36:56]:
  caller: sip:406284@sip.odorik.cz (Johnny English)
  callee: sip:*081@sip.odorik.cz
  duration: 0 years 0 months 0 days 00:00:05
~~~~~~~~~~~~~~~~~~~~~

### Odmítnuté spojení a prozvonění

~~~~~~~~~~~~~~~~~~~~~
# ./sip_monitor -a -i eth0
denied call [Proxy Authentication Required]:
  caller: sip:406284@sip.odorik.cz (Johnny English)
  callee: sip:731251966@sip.odorik.cz
drop-call
  caller: sip:406284@sip.odorik.cz (Johnny English)
  callee: sip:731251966@sip.odorik.cz
~~~~~~~~~~~~~~~~~~~~~

Použitá literatura
==================

#. RFC\ 3261 (SIP)
#. RFC\ 2806 (telephone call URL)
#. RFC\ 793 (TCP)
#. RFC\ 768 (UDP)
#. RFC\ 791 (IPv4)
#. RFC\ 2460 (IPv6)
#. http://www.tcpdump.org/
