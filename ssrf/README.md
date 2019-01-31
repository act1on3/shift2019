# SSRF - Server Side Request Forgery

## Описание

SSRF - уязвимость, позволяющая злоумышленнику спровоцировать сервер на отправку произвольных запросов. Данная уязвимость возникает в функционале, в котором сервер отправляет запрос от своего имени. При этом URL контролируется пользовательским вводом.

## Классификация

1. Basic - показывает ответ на запрос атакующему
2. Blind - запрос происходит, но тела ответа атакующий не видит

## Условия

- ОС: любая
- язык: любой
- компоненты: любые
- настройки: наличие в коде особого функционала

## Детектирование

#### Поиск URL в пользовательском вводе
С помощью Burp Suite смотрим запрос. Можно увидеть, что парсится вся страница яндекса. При этом передается параметр `url` со значением `https://ya.ru`, который мы можем контроллировать.
![Image alt](https://github.com/lifeskipp/shift2019/raw/master/ssrf/images/1_pars.png)

Из этого можно сделать вывод, что мы можем подставить туда произвольный запрос. 

#### Burp Suite Collaborator

С помощью сервера колаборатора можно убедится в том, что запросы приходят к удалённому веб-серверу.
Нужно скопировать payload, который был сгенерирован коллаборатором, нажав: `Copy to Clipboard`

![Image alt](https://github.com/lifeskipp/shift2019/raw/master/ssrf/images/2_2_copy.jpg)

Затем payload нужно вставить в уязвимый параметр (в нашем случае `url`). 

![Image alt](https://github.com/lifeskipp/shift2019/raw/master/ssrf/images/2_3_paste.jpg)

Уязвимый сервер отравил запросы DNS и HTTP

![Image alt](https://github.com/lifeskipp/shift2019/raw/master/ssrf/images/2_collab.png)

Это подтверждает наличие уязвимости.

## Эксплуатация

Существует несколько протоколов, которые можно эксплуатировать для SSRF:
- HTTP/HTTPS - внедрение произвольных GET запросов;
- GOPHER - произвольные TCP пакеты;
- TFTP - произвольные UDP датаграммы;
- File - обращение к диску.	

### HTTP/HTTPS
 
#### Сканирование локалхоста
```
http://127.0.0.1/
http://0.0.0.0/
http://localhost/
```
При этом можно просканировать порты локалхоста на наличие других сервисов.

Обращение делаем с помощью Burp Suite
![Image alt](https://github.com/lifeskipp/shift2019/raw/master/ssrf/images/3_localhost.png)

#### Обход проверки IP-адреса

Если сервер для доступа к определенным путям использует проверку по IP, то с использованием SSRF существует возможность обойти проверку.

Например: так как у нас есть исходный код, мы можем заметить в нём интересные детали, а именно:
```python
@app.route("/secret")
def secret():

	ip = request.remote_addr

	if ip == '127.0.0.1':

		is_secret_view = False

		if request.args.get('show_me_secrets') == 'true':
			is_secret_view = True

		return render_template('secret.html', ip=ip, is_secret_view=is_secret_view)

	else:
		return 'Forbidden', 403
```
Здесь видно, что мы довольно легко можем получить доступ к админке, изменив занчение `url` на: `http://127.0.0.1/secret?show_me_secrets=true`
![Image alt](https://github.com/lifeskipp/shift2019/raw/master/ssrf/images/4_admin.png)

#### Облачные API

Если у сервера есть доступ к облачному API, то можно получить секретную информацию по управлению сервером, и в конечном итоге возможно осуществить RCE.

Список возможных URL для доступа к облачным API [здесь](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery#ssrf-url-for-cloud-instances)

#### Скан сети

Формируя запросы на разные порты и IP-адреса внутренней сети, можно понять инфраструктуру этой сети.

Использование протоколы HTTP/HTTPS для эксплуатации SSRF мы получаем наибольший профит. Можно использовать и другие протоколы, например: TCP, UDP и т.д., но использованием многих протоколов имеет очень много ограничений.

### File

Библиотека cURL позволяет работать с другими протоколами (не только с HTTP/HTTPS). Благодаря этому можно обратится к диску и получать информацию с файловой системы. Например, с помощью замены значения параметра `url` на: `file:///app/main.py`

Библиотека requests так сделать не позволяет.

![Image alt](https://github.com/lifeskipp/shift2019/raw/master/ssrf/images/5_file.jpg)

## Ущерб

Злоумышленник может отправлять запросы во внутреннюю сеть или подсеть, просканировать порты и саму сеть.
Так же злоумышленник с помощью SSRF может выполнять произвольные HTTP GET-запросы.
Можно получить доступ к различным закрытым путям или облачным API.
Если библиотека поддерживает разные схемы, то есть возможность:
- читать локальные файлы
- формировать TCP/UDP пакеты

## Защита
### Основные меры

- Проверять схему в ссылке и работать только с HTTP/HTTPS
- Проверять адрес в ссылке и блокировать запросы на внутренние подсети
(192.168.0.0/16, 172.16.0.0/12, 10.0.0.0/8, 127.0.0.0/8 и т.д.)
НО от данной атаки на 100% защититься нельзя

### Превентивные меры
Вынести сервер, обрабатыващий URL в отдельный сегмент сети, в котором не будет доступа к внутренней сети.

## Дополнительно
 Описание от DSec: https://dsec.ru/wp-content/uploads/2018/09/techtrain_ssrf.pdf  
 Описание, пейлоады, техники: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery

## Обход защиты
- Сокращения
```
http://127.1/
http://0/
```
![Image alt](https://github.com/lifeskipp/shift2019/raw/master/ssrf/images/6_0.png)
![Image alt](https://github.com/lifeskipp/shift2019/raw/master/ssrf/images/6_1.png)

- Представление не в десятичной форме
```
http://0177.1/
http://0x7f.1/
http://2130706433/
```
![Image alt](https://github.com/lifeskipp/shift2019/raw/master/ssrf/images/6_2.png)
![Image alt](https://github.com/lifeskipp/shift2019/raw/master/ssrf/images/6_3.png)
![Image alt](https://github.com/lifeskipp/shift2019/raw/master/ssrf/images/6_4.png)