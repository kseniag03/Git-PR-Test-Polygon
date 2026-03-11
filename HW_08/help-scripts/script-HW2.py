import sys

from scapy.layers.inet import IP, TCP
from scapy.sendrecv import sr1, send
from scapy.utils import rdpcap
import random


# Проверяем наличие обязательных аргументов
if len(sys.argv) < 2:
    print("Необходимо указать адрес назначения (домен или IP).")
    exit()

dest = sys.argv[1]

# Обрабатываем возможный пользовательский HTTP-запрос
try:
    if sys.argv[2]:
        getStr = sys.argv[2]
except IndexError:
    getStr = 'GET / HTTP/1.1\r\nHost: {}\r\nAccept-Encoding: gzip, deflate\r\n\r\n'.format(dest)

# Определяем максимальное количество запросов
try:
    max = int(sys.argv[3])
except ValueError:
    print("Максимальное количество запросов должно быть числом!")
    exit()
except IndexError:
    max = 10

counter = 0
while counter < max:
    # Отсылаем SYN-пакет
    syn = IP(dst=dest) / TCP(sport=random.randint(1025, 65500), dport=80, flags='S')
    # Получаем SYN-ACK
    syn_ack = sr1(syn, timeout=5)
    if syn_ack is None:
        print(f"Нет ответа SYN-ACK от {dest}. Пропускаю итерацию.")
        continue

    # Отправляем ACK-пакет
    ack_packet = IP(dst=dest) / TCP(dport=80, sport=syn_ack[TCP].sport, seq=syn_ack[TCP].ack, ack=(syn_ack[TCP].seq + 1), flags='A')
    send(ack_packet, verbose=False)

    # Отправляем HTTP GET-запрос
    http_request = IP(dst=dest) / TCP(dport=80, sport=syn_ack[TCP].sport, seq=syn_ack[TCP].ack, ack=(syn_ack[TCP].seq + 1), flags='PA') / getStr
    response = sr1(http_request, timeout=5)
    if response:
        print(response.summary())
    else:
        print("Нет ответа после отправки HTTP GET.")

    counter += 1


















