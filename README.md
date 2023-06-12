# OPIS PROJEKTU

Implementacja systemu detekcji skanowania portów z pojedynczego źródła, z wykorzystaniem metod statystycznych w oparciu o algoryt  **TRW** (*ang. "threshold random walk"*)  zaproponowany przez J. Jung, V. Paxson, A. W. Berger, H. Balakrishnan w pracy "Fast portscan detection using sequential hypothesis testing.", wraz z  jego modyfikacją pozwalającą na wykrywanie skanów wertykalnych (**TRWP**).





pip install -r requirements.txt

## Zawartość repozytorium

### Katalogi
[datasets](datasets) - wykorzystane zbiory testowe\
[src](src) - pliki źródłowe aplikacji

### Skrypty
[main.py](main.py) - główny plik służący do uruchomienia aplikacji\
[test_cicids2017.py](test_cicids2017.py) - skrypt wykorzystany do przeprowadzenia testów na zbiorze CICIDS2017\oraz testów wydajnościowych\
[test_port_stats.py](test_port_stats.py) - skrypt wykorzystany do przeprowadzenia badań statystycznych\
[CICIDS2017_raw_wisdom.txt](CICIDS2017_raw_wisdom.txt) - plik z listą wiedzy dla wyroczni na potrzeby testów na zbiorze CICIDS2017\
[conf.ini](conf.ini) - domyślny plik konfiguracyjny\
[conf_CICIDS.ini](conf_CICIDS.ini) - plik konfiguracyjny dla zbioru CICIDS2017



### Pliki źródłowe



[conf_reader.py](src/conf_reader.py) - klasa odpowiedzialna za wczytywanie konfiguracji\
[sniffer.py](src/sniffer.py) - klasa odpowiedzialna za przechwytywanie ruchu sieciowego\
[packets_manager.py](src/packets_manager.py) - klasa odpowiedzialna za wstępną analizę \pakietów i przekazywanie do odpowiednich procesorów
[packet_processor.py](src/packet_processor.py) - klasa bazowa procesora do właściwej analizy \ruchu
[trw_processor.py](src/trw_processor.py) - klasa procesora analizującego ruch z \wykorzytsaniem **TRW** i **TRWP**
[trw.py](src/trw.py) - realizacja algorytmów **TRW** i **TRWP**\
[network_oracle.py](src/network_oracle.py) - wyrocznia dla algorytmów **TRW** I **TRWP**