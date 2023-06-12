# OPIS PROJEKTU

Implementacja systemu detekcji skanowania portów z pojedynczego źródła, z wykorzystaniem metod statystycznych w oparciu o algoryt  **TRW** (*ang. "threshold random walk"*)  zaproponowany przez J. Jung, V. Paxson, A. W. Berger, H. Balakrishnan w pracy "Fast portscan detection using sequential hypothesis testing.", wraz z  jego modyfikacją pozwalającą na wykrywanie skanów wertykalnych (**TRWP**).





## Zawartość repozytorium

### Katalogi
[datasets](datasets) - wykorzystane zbiory testowe\
[src](src) - pliki źródłowe aplikacji

### Skrypty
- [main.py](main.py) - **plik main** służący do uruchomienia aplikacji
- [test_cicids2017.py](test_cicids2017.py) - skrypt wykorzystany do przeprowadzenia testów na zbiorze CICIDS2017oraz testów wydajnościowych
- [test_port_stats.py](test_port_stats.py) - skrypt wykorzystany do przeprowadzenia badań statystycznych
- [CICIDS2017_raw_wisdom.txt](CICIDS2017_raw_wisdom.txt) - plik z listą wiedzy dla wyroczni na potrzeby testów na zbiorze CICIDS2017
- [conf.ini](conf.ini) - domyślny plik konfiguracyjny
- [conf_CICIDS.ini](conf_CICIDS.ini) - plik konfiguracyjny dla zbioru CICIDS2017



### Pliki źródłowe



- [conf_reader.py](src/conf_reader.py) - klasa odpowiedzialna za wczytywanie konfiguracji
- [sniffer.py](src/sniffer.py) - klasa odpowiedzialna za przechwytywanie ruchu sieciowego
- [packets_manager.py](src/packets_manager.py) - klasa odpowiedzialna za wstępną analizę pakietów i przekazywanie do odpowiednich procesorów
- [packet_processor.py](src/packet_processor.py) - klasa bazowa procesora do właściwej analizy ruchu
- [trw_processor.py](src/trw_processor.py) - klasa procesora analizującego ruch z wykorzytsaniem **TRW** i **TRWP**
- [trw.py](src/trw.py) - realizacja algorytmów **TRW** i **TRWP**
- [network_oracle.py](src/network_oracle.py) - wyrocznia dla algorytmów **TRW** I **TRWP**


## Uruchomienie aplikacji

Do napisania i testowania aplikacji wykorzystano **Python3.11** oraz oprogramowanie [**ncap-1.75**](https://npcap.com/).
System uruchomiony został w systemi Windows 10.

Wszystkie zależności wymagane do uruchomienia zawarto w pliku [requirements.txt](requirements.txt).


Przed uruchomieniem należy utworzyć plik z wiedzą dla wyroczni oraz plik konfiguracyjny systemu.\
Plik wiedzy zawiera listę wpisów informujących system o otwartych portach w ramach chronionej sieci.
Wpisy należy umieszczać w formacie `adres_ip:port` odzielonymi znakiem nowej lini. Za pomocą symbolu `#` można dodać komentarz.

**Przykładowy plik wiedzy**

```log
192.168.1.5:213
192.168.1.3:2112
192.168.1.3:21333
#komentarz
192.168.1.23:21333

```

**Przykładowy plik konfiguracyjny**
```ini
[SNIFFER]
# maksymalna liczba pakietów zarejestrowana przez sniffer
# 0 - no limit
max_packets=0 


[TRW_PROCESSOR]
Pd = 0.99
Pf = 0.01
theta0 = 0.8
theta1 = 0.2
#źródło wiedzy wyroczni
oracle_source = local_wisdom.txt
# maska chronionej sieci
local_network = 192.168.1.0/24
#liczba aktualizacji stanu po której następuję zrzut do pliku
stats_dump_period = 500
```


**Uruchomienie aplikacji**
```bash
python main.py conf.ini
```



### Wynik działania aplikacji

Podczas działania aplikacji powstają cztery pliki robocze:
- [status.json]() - zrzut stanu wiedzy dla metody **TRW**
- [status_ports.json]() - zrzut stanu wiedzy dla metody **TRWP**
- [detected.log]() - plik z logami zawierający informację o wykrytych skanach dla metody **TRW**
- [detected_ports.log]() - plik z logami zawierający informację o wykrytych skanach dla metody **TRWP**

Aplikacja po uruchomieniu wczytuję poprzednio uzyskany stan wiedzy jeśli znajdzie odpowiedni plik. 
Stan wiedzy zapisywany jest w formacie **json** pozwalającym na jego wygodne przeglądanie.
W celu zresetowania stanu należy usunąć odpowiedający plik.













