# Sieci komputerowe 2

## Prosty serwer i klient HTTP 

Projekt stworzony na potrzeby laboratorium Sieci komputerowe 2 w semestrze zimowym 2023/2024.

Serwer jest zaimplementowany w C++ / C (TODO: zobaczy się) i został przetestowany pod systemem GNU/Linux (TODO: jakie distro?).

Klient jest zaimplementowany w Python 3 i został przetestowany pod systemem Windows 10. 

## Budowanie projektu


### Serwer (GNU/Linux)

```bash
cd server
./run.sh
```

### Klient (Windows)

```bat
cd client
pip install -r requirements.txt
run.cmd
```

Chromium służy jako front-end naszej aplikacji, jest wykorzystywane przez pakiet `eel`. **Przeglądarka nie wykonuje żadnych zapytań do serwera, odpowiada wyłącznie za aspekt wizualny.** Za komunikację z serwerem odpowiadają sockety.

W przypadku błędu `OSError: Can't find Google Chrome/Chromium installation`, klient musi mieć zainstalowanego Chrome. 

Jeśli program nie wykrywa ścieżki do Chrome, problem można rozwiązać następującym snippetem:

```python
import eel.browsers
eel.browsers.set_path('chrome', '/path/to/your/exe')
```

## Opis protokołu HTTP

TODO

## Opis implementacji, w tym krótki opis zawartości plików źródłowych

TODO

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
-  Programy muszą być napisane w sposób czytelny i przejrzysty, należy umieszczać stosowne komentarze w kodzie, a także warto stosować styl kodowania wypracowany przez firmę Google
- Do każdego projektu należy dołączyć krótkie sprawozdanie (maksymalnie jedna strona formatu A4) w formacie PDF lub jako plik README.txt, które ma zostać umieszczone w repozytorium projektu zaliczeniowego. W sprawozdaniu tym należy zawrzeć następujące informacje:
  - temat zadania
  - opis protokołu komunikacyjnego
  - opis implementacji, w tym krótki opis zawartości plików źródłowych
  - sposób kompilacji, uruchomienia i obsługi programów projektu
- Co najmniej dwa dni przed planowanym terminem zaliczania projektu należy wysłać e-mail doprowadzącego zajęcia zawierający nazwę oraz adres repozytorium projektu zaliczeniowego w systemie GitLab. W temacie wiadomości e-mail proszę wpisać: [SK2] Projekt zaliczeniowy. Uwaga: należy dodać prowadzącego zajęcia jak członka grupy projektu w systemie GitLab z uprawnieniami „Developer”.

## Kryteria oceny projektu

*Skopiowane ze strony prowadzącego:*

- Poprawność implementacji projektu, a w szczególności komunikacji sieciowej.
- Poprawność protokołu komunikacyjnego.
- Zgodność funkcjonalności projektu z uzgodnionymi wymaganiami.
- Przejrzystość i czytelność kodu.
- Inicjatywa i pomysłowość w realizacji projektu.
- Przestrzeganie zasad zaliczania projektu.

## Autorzy

- Maciej Kaszkowiak 
- Adam Jałocha

## Licencja

Projekt jest pod licencją MIT, zgodnie z plikiem LICENSE.

## Odnośniki

- [RFC 2616](https://datatracker.ietf.org/doc/html/rfc2616)
- [Projekty zaliczeniowe z laboratorium sieci komputerowych II](https://www.cs.put.poznan.pl/mkalewski/edu/sk/doc/zadania.pdf)
