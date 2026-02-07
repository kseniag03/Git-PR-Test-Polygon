import argparse
import gzip
import io
import socket
import random
import time
from urllib.parse import urlparse
from scapy.layers.inet import IP, TCP
from scapy.sendrecv import sr1, send
from scapy.all import sniff, wrpcap, rdpcap


def resolve_hostname(hostname):
    """Разрешает доменное имя в IP-адрес."""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror as e:
        print(f"Ошибка разрешения доменного имени '{hostname}': {e}")
        return None


def parse_url(url_arg):
    """Парсит URL и извлекает hostname, path и scheme."""
    if not url_arg.startswith('http://') and not url_arg.startswith('https://'):
        url_arg = 'http://' + url_arg
    
    try:
        parsed = urlparse(url_arg)
        hostname = parsed.hostname
        path = parsed.path if parsed.path else '/'
        scheme = parsed.scheme or 'http'
        return hostname, path, scheme
    except Exception as e:
        print(f"Ошибка парсинга URL: {e}")
        return None, None, None


def send_http_request(hostname, path, custom_request=None):
    """Отправляет HTTP-запрос через Scapy."""
    dest_ip = resolve_hostname(hostname)
    if not dest_ip:
        return None
    
    port = 80
    client_sport = random.randint(1025, 65500)
    
    # Формируем HTTP-запрос
    if custom_request:
        http_request_str = custom_request
    else:
        http_request_str = f'GET {path} HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n'
    
    # Устанавливаем TCP-соединение
    syn = IP(dst=dest_ip) / TCP(sport=client_sport, dport=port, flags='S')
    syn_ack = sr1(syn, timeout=5, verbose=False)
    
    if not syn_ack or not syn_ack.haslayer(TCP) or syn_ack[TCP].flags != 0x12:
        print(f"Не удалось установить соединение с {hostname}")
        return None
    
    # Отправляем ACK
    client_seq = syn_ack[TCP].ack
    client_ack = syn_ack[TCP].seq + 1
    ack_packet = IP(dst=dest_ip) / TCP(
        sport=client_sport,
        dport=port,
        seq=client_seq,
        ack=client_ack,
        flags='A'
    )
    send(ack_packet, verbose=False)
    
    time.sleep(0.1)
    
    # Отправляем HTTP-запрос
    http_request = IP(dst=dest_ip) / TCP(
        sport=client_sport,
        dport=port,
        seq=client_seq,
        ack=client_ack,
        flags='PA'
    ) / http_request_str
    
    send(http_request, verbose=False)
    
    return dest_ip, port, client_sport


def capture_traffic(hostname, timeout=30, output_file=None):
    """Перехватывает HTTP-трафик для указанного хоста."""
    dest_ip = resolve_hostname(hostname)
    if not dest_ip:
        return None
    
    print(f"Начало перехвата трафика для {hostname} ({dest_ip})...")

    packets = sniff(
        filter=f"host {dest_ip} and (tcp port 80 or tcp port 443)",
        timeout=timeout
    )
    
    print(f"Перехвачено пакетов: {len(packets)}")
    
    if output_file and packets:
        wrpcap(output_file, packets)
        print(f"Трафик сохранен в {output_file}")
    
    return packets


def analyze_packets(packets):
    """Базовый анализ перехваченных пакетов."""
    if not packets:
        print("Нет пакетов для анализа")
        return
    
    http_data = []

    for pkt in packets:
        if not (pkt.haslayer("TCP") and pkt.haslayer("IP") and pkt.haslayer("Raw")):
            continue

        tcp = pkt["TCP"]

        # анализируем только HTTP (порт 80) — и ответы, и запросы
        if tcp.dport != 80 and tcp.sport != 80:
            continue

        raw = bytes(pkt['Raw'].load)

        if raw.startswith(b"GET ") or raw.startswith(b"POST ") or raw.startswith(b"HTTP/"):
            http_data.append(raw)
    
    print(f"Найдено HTTP-сообщений: {len(http_data)}")

    for i, raw in enumerate(http_data[:3], 1):
        # Заголовки печатаем как текст (без потерь байт)
        text = raw.decode("iso-8859-1", errors="replace")

        print(f"HTTP-сообщение {i} (первые 300 символов)")
        print(text[:300])

        # GZIP
        if raw.startswith(b"HTTP/") and (b"content-encoding: gzip" in raw.lower()):
            try:
                if b"\r\n\r\n" in raw:
                    head_bytes, body_bytes = raw.split(b"\r\n\r\n", 1)
                else:
                    head_bytes, body_bytes = raw.split(b"\n\n", 1)

                buf = bytearray(body_bytes)

                # пытаемся дозабрать тело из Raw-пакетов (упрощённо)
                decompressed = gzip.decompress(bytes(buf))

                print("\nРаспакованное gzip-тело ответа (первые 300 символов):")
                print(decompressed.decode("utf-8", errors="ignore")[:300])

            except Exception:
                print("\nНе удалось распаковать gzip-тело ответа (возможна фрагментация по TCP)")
    
    # TODO для этапа 4: добавить анализ на наличие XSS-полезных нагрузок
    # TODO для этапа 4: добавить поиск отраженных XSS в ответах сервера
    xss_markers = [
        b"<script",
        b"</script>",
        b"alert(",
        b"onerror=",
        b"onload="
    ]

    for data in http_data:
        lower = data.lower()

        for marker in xss_markers:
            if marker in lower:
                print("\nПодозрение на наличие XSS-полезных нагрузок в HTTP-запросе")
                print(f"Маркер: {marker.decode('ascii', errors='ignore')}")
                print("Фрагмент запроса:")
                print(data[:1500].decode("iso-8859-1", errors="replace"))

        if data.startswith(b"HTTP/"):
            for marker in xss_markers:
                if marker in lower:
                    print("\nПодозрение на наличие отраженных XSS в ответах сервера")
                    print(f"Маркер: {marker.decode('ascii', errors='ignore')}")
                    print("Фрагмент ответа:")
                    print(data[:1500].decode("iso-8859-1", errors="replace"))


def analyze_saved_traffic(pcap_file):
    """Анализирует сохраненный трафик из .pcap файла."""
    print(f"Анализ трафика из файла: {pcap_file}")
    packets = rdpcap(pcap_file)
    analyze_packets(packets)


def main():
    parser = argparse.ArgumentParser(
        description='Анализ XSS-уязвимостей с использованием Scapy',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
            Примеры использования:
            # Отправка HTTP-запроса
            python scapy_xss_analyzer.py --send google-gruyere.appspot.com/XXXXX
            
            # Перехват трафика
            python scapy_xss_analyzer.py --capture google-gruyere.appspot.com --timeout 60 --output traffic.pcap
            
            # Анализ сохраненного трафика
            python scapy_xss_analyzer.py --analyze traffic.pcap
        """
    )
    
    parser.add_argument(
        '--send',
        metavar='URL',
        help='Отправить HTTP-запрос на указанный URL'
    )
    
    parser.add_argument(
        '--capture',
        metavar='HOSTNAME',
        help='Перехватить трафик для указанного хоста'
    )
    
    parser.add_argument(
        '--analyze',
        metavar='PCAP_FILE',
        help='Проанализировать сохраненный трафик из .pcap файла'
    )
    
    parser.add_argument(
        '--timeout',
        type=int,
        default=30,
        help='Таймаут для перехвата трафика в секундах (по умолчанию: 30)'
    )
    
    parser.add_argument(
        '--output',
        metavar='FILE',
        help='Имя файла для сохранения перехваченного трафика'
    )
    
    parser.add_argument(
        '--request',
        metavar='HTTP_REQUEST',
        help='Кастомный HTTP-запрос (для этапа 3)'
    )
    
    args = parser.parse_args()
    
    # Проверка аргументов
    if not any([args.send, args.capture, args.analyze]):
        parser.print_help()
        return
    
    # Отправка HTTP-запроса
    if args.send:
        hostname, path, scheme = parse_url(args.send)
        if not hostname:
            print("Ошибка: не удалось распарсить URL")
            return
        
        print(f"Отправка HTTP-запроса на {hostname}{path}")
        result = send_http_request(hostname, path, args.request)
        if result:
            print("HTTP-запрос отправлен")
        else:
            print("Ошибка при отправке HTTP-запроса")
    
    # Перехват трафика
    if args.capture:
        packets = capture_traffic(args.capture, args.timeout, args.output)
        if packets:
            analyze_packets(packets)
    
    # Анализ сохраненного трафика
    if args.analyze:
        analyze_saved_traffic(args.analyze)


if __name__ == '__main__':
    main()

