# Prosty serwer i klient HTTP 

Projekt stworzony na potrzeby laboratorium Sieci komputerowe 2 w semestrze zimowym 2023/2024.

## Serwer (GNU/Linux)

Serwer jest zaimplementowany w C i został przetestowany pod systemami GNU/Linux (Ubuntu 20.04.6 LTS) i MacOS 14.

Serwer został zaimplementowany zgodnie z RFC 2616, przez co można z niego korzystać za pośednictwem serwera lub curl, np:

### GET
```
curl -i localhost:2138/<sciezka>
```

### HEAD
```
curl -i -X HEAD localhost:2138/<sciezka>
```

### PUT
```
curl --header "Content-Type: application/octet-stream" -i -X PUT --data-binary @plik localhost:2138/<sciezka>
```

### DELETE
```
curl -i -X DELETE localhost:2138/<sciezka>
```

Serwer działa na zasadzie forkowania; tworzy nowy proces potomny (dziecko) dla każdego przychodzącego połączenia.

### Uruchomienie 

```bash
cd server
./run.sh
```

### Struktura plików

- **main.c** - glówna część, uruchomiająca serwer i nasłuchująca na zapytania klienta
- **resources/** - Zasoby na których klient może wykonywać operacje GET, HEAD, PUT, DELETE

## Klient (Windows)

Klient jest zaimplementowany w Python 3.9 i został przetestowany pod systemem Windows 10.

Do komunikacji z serwerem posługuje się biblioteką `sockets`, która pod Windowsem wykorzystuje interfejs WinSock. GUI wykorzystuje bibliotekę `eel`, która jest Pythonowym odpowiednikiem Electrona.

Pakiet `eel` do wyświetlania GUI wykorzystuje Chromium. **Przeglądarka nie wykonuje żadnych zapytań do serwera, odpowiada wyłącznie za aspekt wizualny.** Za komunikację z serwerem odpowiadają wyłącznie sockety, zgodnie z wymaganiami zadania.

### Uruchomienie
```bat
cd client
pip install -r requirements.txt
run.cmd
```

### Struktura plików

- **main.py** - glówna część, uruchomiająca GUI oraz przetwarzająca jego komendy
- **http_parser.py** - parser do przetwarzania raw payloadu HTTP w obiekt z danymi
- **client.py** - klient oparty o sockets do komunikacji ze serwerem 
- web/ - pliki serwowane przez eel
  - **web/index.html** - frontend klienta


### Troubleshooting

W przypadku błędu `OSError: Can't find Google Chrome/Chromium installation`, klient musi mieć zainstalowanego Chrome. 

Jeśli program pomimo tego nie wykrywa ścieżki do Chrome, problem można rozwiązać następującym snippetem:

```python
import eel.browsers
eel.browsers.set_path('chrome', '/path/to/your/exe')
```

## Protokół serwer - klient

Zapytania do bazy wymagają nagłówka HOST zgodnie z http rfc 2616.

### Ogólne zasady:
  - Wspierane metody to GET, HEAD, PUT, DELETE, gdy spróbujemy skorzystać z innej otrzymamy błąd 405 Method Not Allowed.
  - W przypadku gdy podamy nie istniejącą sciezke dla zapytań GET, HEAD, DELETE otrzymamy błąd 404 Not Found.

  - ```GET /<sciezka do pliku>```
    - Pobierze treść pliku zlokalizowanego w folderze zasobów, mającego format binarny "application/octet-stream". Klient odbiera odpowiedź od serwera i prezentuje wynik wraz z nagłówkami w interfejsie graficznym (GUI).

  - ```HEAD /<sciezka do pliku>```
    - Pobierze informacje o pliku zlokalizowanego w katalogu zasobów. Klient otrzyma odpowiedź z serwera, ale nie pobierze faktycznej zawartości pliku, a jedynie nagłówki, które zostaną wyświetlone w interfejsie graficznym (GUI).

  - ```PUT /<sciezka do pliku>```
    - Przekazany plik w body w postaci binarnej zostaje odebrany przez serwer i umieszcza go pod wybrana ściezką w folderze zasobów. W przypadku gdy plik juz istniał zostaje zastąpiony nową wersją pliku.
    - Przy korzystaniu z metody wymagany jest nagłówek Content-Length zawierający prawidłową wartość w innym przypadku serwer zwróci 400 Bad Request. W przypadku gdy nagłówek nie zostanie podany otrzymamy 411 Length Required.

  - ```DELETE /<sciezka do pliku>```
    - Serwer podejmuje próbę usunięcia pliku podanego w ściezce, w przypadku gdy plik istnieje zostanie on usunięty i serwer wyśle odpowiedź 200 OK.

## Istotne funkcjonalności
- Zabezpieczenie przed atakiem directory traversal (GET ../../../../../../etc/passwd)
- Konfigurowalny maksymalny limit body
- Konfigurowalny maksymalny limit nagłówków (z poprawną odpowiedzią HTTP 431)
- Zabezpieczenie przed przepełnieniem RAM - uniemożliwienie przesłania za dużego payloadu
- Konfigurowalny timeout, zabezpieczający przed zawieszeniem połączeń
- Obsługa nagłówka 100 Continue
- Przetwarzanie nagłówków z delimeterem zarówno CRLF jak i LF, zgodnie z pkt 10.3 RFC 2616
- Wymuszanie nagłówka Host:, zgodnie z pkt 19.6.1.1 RFC 2616
---


## Wymagania 

*Skopiowane ze strony prowadzącego:*

**Prosty serwer protokołu HTTP zgodny ze specyfikacją RFC 2616 co najmniej w zakresie żądań: GET, HEAD, PUT, DELETE (2 osoby).**

- Projekt należy zrealizować w architekturze klient-serwer z użyciem protokołu TCP
- Implementacje serwerów współbieżnych należy wykonać dla systemów operacyjnych GNU/Linux z użyciem języka C lub C++
- implementacje aplikacji klientów dla systemów Microsoft Windows z użyciem języka C, C++, C#, Java lub Python z graficznym interfejsem użytkownika
- Kody projektów muszą być utrzymywane w repozytorium git2 w systemie GitLab: https://gitlab.cs.put.poznan.pl.
- Wszystkie programy muszą się poprawnie i bez ostrzeżeń (z opcją -Wall dla języków C i C++) kompilować na komputerach laboratoryjnych
- Podczas zaliczania, programy będą uruchamiane tylko na komputerach laboratoryjnych (wyjątkiem są urządzenia mobilne)
- Programy muszą być napisane w sposób czytelny i przejrzysty, należy umieszczać stosowne komentarze w kodzie, a także warto stosować styl kodowania wypracowany przez firmę Google
- Do każdego projektu należy dołączyć krótkie sprawozdanie (maksymalnie jedna strona formatu A4) w formacie PDF lub jako plik README.txt, które ma zostać umieszczone w repozytorium projektu zaliczeniowego. W sprawozdaniu tym należy zawrzeć następujące informacje:
  - temat zadania
  - opis protokołu komunikacyjnego
  - opis implementacji, w tym krótki opis zawartości plików źródłowych
  - sposób kompilacji, uruchomienia i obsługi programów projektu
- Co najmniej dwa dni przed planowanym terminem zaliczania projektu należy wysłać e-mail doprowadzącego zajęcia zawierający nazwę oraz adres repozytorium projektu zaliczeniowego w systemie GitLab. W temacie wiadomości e-mail proszę wpisać: [SK2] Projekt zaliczeniowy. Uwaga: należy dodać prowadzącego zajęcia jak członka grupy projektu w systemie GitLab z uprawnieniami „Developer”.

### Kryteria oceny projektu

*Skopiowane ze strony prowadzącego:*

- Poprawność implementacji projektu, a w szczególności komunikacji sieciowej.
- Poprawność protokołu komunikacyjnego.
- Zgodność funkcjonalności projektu z uzgodnionymi wymaganiami.
- Przejrzystość i czytelność kodu.
- Inicjatywa i pomysłowość w realizacji projektu.
- Przestrzeganie zasad zaliczania projektu.

## Potencjalne usprawnienia

- Ograniczenie liczby jednoczesnych połączeń - aktualnie bardzo łatwo jest zDoSować nasz serwer

## Autorzy

- Maciej Kaszkowiak 
- Adam Jałocha

## Licencja

Projekt jest objęty licencją MIT - szczegóły w pliku LICENSE.

## Odnośniki

- [RFC 2616](https://datatracker.ietf.org/doc/html/rfc2616)
- [Projekty zaliczeniowe z laboratorium sieci komputerowych II](https://www.cs.put.poznan.pl/mkalewski/edu/sk/doc/zadania.pdf)
