# SHIFT AppSec 2019

## Стек технологий
- Python3 + Flask ([uwsgi-nginx-flask-docker](https://github.com/tiangolo/uwsgi-nginx-flask-docker))
- Docker
- Git
- Firefox
- Burp Suite
- некоторые зависимости для python

## Как работаем
Шаги:
1) Регистрируемся на [github.com](https://github.com), если нет аккаунта
2) Отправляем мне в телеграмм свой никнейм на Github (или линк на Github)
3) Я добавляю вас в контрибьюторы проекта, вы сможете вносить изменения
4) Клонируем репозиторий
5) Переходим (создаем) в директорию с названием уязвимости (если создаем, то используем lowercase и `_` вместо пробелов, например `jwt_insecure`)
6) Переключаемся на новую ветку. Имя ветки лучше выбрать такое же, как и директорию
7) Копируем шаблон `../example/README.md` в свою рабочую директорию
8) Используем директорию, редактируем `README.md`, ресерчим!

---
**Запрещается:**
- изменять файлы в чужой рабочей директории (чужая уязвимость)
- сохранять нетекстовые файлы (исключение - картинки)
- лучше не переводить на русский специфичные определения
---

## Шпаргалка
### Markdown
Для написания информации по ресерчу используем Markdown-разметку.
Что понадобится:
- шпаргалка по синтаксису есть [тут](https://github.com/adam-p/markdown-here/wiki/Markdown-Cheatsheet)
- лучше использовать удобный текстовый редактор (я использую [Sublime Text](https://www.sublimetext.com/))
- лучше в текстовом редакторе поставить плагин для предпроссмотра Markdown-файлов (я использую [этот](https://packagecontrol.io/packages/MarkdownPreview))

### Python
Будем использовать Python + Flask.

Установка окружения:
- Windows http://timmyreilly.azurewebsites.net/python-pip-virtualenv-installation-on-windows/
- Linux https://itsfoss.com/python-setup-linux/

Создать виртуальное окружение (можно без него, тогда надо использовать `pip3`):
- `cd <directory>`
- `virualenv`

Появится директория `venv` со структурой:
```
├── bin
│   ├── activate
│   ├── activate.csh
│   ├── activate.fish
│   ├── easy_install
│   ├── easy_install-3.6
│   ├── flask
│   ├── pip
│   ├── pip3
│   ├── pip3.6
│   ├── python
│   ├── python3
│   └── python3.6
├── include
├── lib
│   └── python3.6
├── lib64 -> lib
├── pip-selfcheck.json
└── pyvenv.cfg
```

Используем бинарники отсюда: `venv/bin/`

Установить Flask:
- `venv/bin/pip3 install flask`

### Git
Установка: https://git-scm.com/book/ru/v1/%D0%92%D0%B2%D0%B5%D0%B4%D0%B5%D0%BD%D0%B8%D0%B5-%D0%A3%D1%81%D1%82%D0%B0%D0%BD%D0%BE%D0%B2%D0%BA%D0%B0-Git

Указание авторства:
- `git config --global user.name "<your_nickname>"`
- `git config --global user.email "<your_email>"`

Клонирование репозитория:
- `git clone https://github.com/act1on3/shift2019.git`

Перейти на новую ветку:
- `git checkout -b <branch_name>`
- `git push --set-upstream origin <branch_name>`

Обновить локальный репозиторий из удаленного:
- `git pull`

Добавление измененных файлов и коммит своих изменений:
- `git status`
- `git add <filename>`
- `git commit`
- пишете описание коммита

Отправка локальных изменений в репозиторий:
- `git push`


### Docker
Установка: 
- Windows https://docs.docker.com/docker-for-windows/install/
- Ubuntu https://docs.docker.com/install/linux/docker-ce/ubuntu/
- Debian https://docs.docker.com/install/linux/docker-ce/debian/
- MacOS https://docs.docker.com/docker-for-mac/install/

Создать образ:
- `cd open_redirect`
- `docker build -t open_redirect .`
- `docker run -p 8080:80 open_redirect` или добавить ключ `-d` для отправки в daemon-режим

Закрыть все контейнеры:
- ```docker rm -f `docker ps -a -q` ```

Удалить образы:
- `docker images`
- `docker image rm <image_name>`

Удалить все промежуточные образы (создаются во время билда):
- ```docker rmi `docker images -f "dangling=true" -q` ```


## Информация для ресерча
### Open redirect
Ссылки:
- Интерактивный урок: https://www.hacksplaining.com/exercises/open-redirects
- Описание, детектирование, пейлоады: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Open%20redirect
- Open Redirect от OWASP: https://www.owasp.org/index.php/Unvalidated_Redirects_and_Forwards_Cheat_Sheet
- Пример репорта баги: https://hackerone.com/reports/387007 и Google Dork `site:hackerone.com open redirect`
- Пейлоады для баг-баунти: https://github.com/EdOverflow/bugbounty-cheatsheet/blob/master/cheatsheets/open-redirect.md
- Статья с дополнительными фишками (обходы фильтров): https://medium.com/bugbountywriteup/cvv-2-open-redirect-213555765607
- Дополнительная информация: https://2017.zeronights.org/wp-content/uploads/materials/ZN17_Karbutov_CRLF_PDF.pdf

### CRLF
Ссылки:
- Расширенное описание: https://prakharprasad.com/crlf-injection-http-response-splitting-explained/
- Описание, основная инфа, пейлоады: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CRLF%20injection
- XSS через CRLF на hackerone: https://vulners.com/hackerone/H1:192749
- Пример репорта баги: Google Dork `site:hackerone.com crlf`
- Шпаргалка от EdOverflow: https://github.com/EdOverflow/bugbounty-cheatsheet/blob/master/cheatsheets/crlf.md
- Дополнительная информация: https://2017.zeronights.org/wp-content/uploads/materials/ZN17_Karbutov_CRLF_PDF.pdf

### SSRF
Ссылки:
- Описание от DSec: https://dsec.ru/wp-content/uploads/2018/09/techtrain_ssrf.pdf
- Описание, пейлоады, техники: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SSRF%20injection/README.md
- Очень дорогой SSRF-баг на hackerone: https://hackerone.com/reports/341876
- A new Era of SSRF by Orange Tsai: https://www.blackhat.com/docs/asia-18/asia-18-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf

### Template Injection
- Статья с описанием от albinowax: https://portswigger.net/blog/server-side-template-injection
- Ресерч, пэйлоады и др: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20injections
- Статья с описанием от defcon.ru: https://defcon.ru/web-security/3840/
- Описание SSTI во Flask: https://nvisium.com/blog/2015/12/07/injecting-flask.html

### CSRF
- Интерактивный урок: https://www.hacksplaining.com/exercises/csrf
- Варианты защиты: https://habr.com/ru/post/318748/
- Описание и защита: https://learn.javascript.ru/csrf
- Обход при эксплуатации при типе данных JSON: https://www.geekboy.ninja/blog/exploiting-json-cross-site-request-forgery-csrf-using-flash/ и https://blog.appsecco.com/exploiting-csrf-on-json-endpoints-with-flash-and-redirects-681d4ad6b31b
- Описание, обход, эксплуатация: https://2017.zeronights.org/wp-content/uploads/materials/ZN17_MikhailEgorov%20_Neat_tricks_to_bypass_CSRF_protection.pdf
- Описание, защита - https://2017.zeronights.org/wp-content/uploads/materials/csrf_cors_etc.pdf

### JWT insecure
- Описание проблем технологии: https://www.slideshare.net/snyff/jwt-insecurity
- Потестировать технологию: https://jwt.io/
- Шпаргалка с чек-листом для тестирования: https://assets.pentesterlab.com/jwt_security_cheatsheet/jwt_security_cheatsheet.pdf
- Описание, информация: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/JSON%20Web%20Token

### PHP Type Juggling
- Описание, таблицы, примеры багов: https://www.owasp.org/images/6/6b/PHPMagicTricks-TypeJuggling.pdf
- Информация об эксплуатации: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/PHP%20juggling%20type

### Deserialization
- Ресерч десериализация в Java: https://github.com/mbechler/marshalsec/blob/master/marshalsec.pdf
- Шпаргалка от OWASP: https://www.owasp.org/index.php/Deserialization_Cheat_Sheet#Guidance_on_Deserializing_Objects_Safely
- Шпаргалка от GrrrDog: https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet
- Уязвимые приложения (Python, nodejs, Java (native binary and jackson)): https://github.com/GrrrDog/ZeroNights-WebVillage-2017
- Ресерч по десериализации в Ruby: https://lab.wallarm.com/exploring-de-serialization-issues-in-ruby-projects-801e0a3e5a0a