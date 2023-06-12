# OPIS PROJEKTU

Implementacja systemu detekcji skanowania portów z pojedynczego źródła, z wykorzystaniem metod statystycznych w oparciu o algoryt TRW zaproponowany przez J. Jung, V. Paxson, A. W. Berger, H. Balakrishnan w pracy "Fast portscan detection using sequential hypothesis testing.", wraz z  jego modyfikacją pozwalającą na wykrywanie skanów wertykalnych.





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



