# SHIFT AppSec 2019

## Стек технологий
- Python3 + Flask
- Docker
- Git
- [uwsgi-nginx-flask-docker](https://github.com/tiangolo/uwsgi-nginx-flask-docker)
- Firefox
- Burp Suite
- некоторые зависимости для python

### Установка
#### Unix based


#### Windows


## Как работаем
Шаги:
1) Регистрируемся на [github.com](https://github.com), если нет аккаунта
2) Отправляем мне в телеграмм свой никнейм на Github (или линк на Github)
3) Я добавляю вас в контрибьюторы проекта, вы сможете вносить изменения
4) Клонируем репозиторий
5) Создаем директорию с названием уязвимости (используем lowercase и `_` вместо пробелов, например `jwt_insecure`)
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

### Git
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