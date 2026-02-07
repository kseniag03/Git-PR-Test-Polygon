# Отчёт ДЗ №8

## Запуск скриптов с захватом и отдельно анализом:
```sh
sudo venv/bin/python scapy_xss_analyzer.py --capture google-gruyere.appspot.com --timeout 60 --output normal.pcap
sudo venv/bin/python scapy_xss_analyzer.py --capture google-gruyere.appspot.com --timeout 60 --output xss.pcap
sudo venv/bin/python scapy_xss_analyzer.py --analyze normal.pcap
sudo venv/bin/python scapy_xss_analyzer.py --analyze xss.pcap
```

## HTTP-запрос с XSS-полезной нагрузкой:
- Метод запроса: **POST**
- Endpoint: POST /637068462530943849873341858010451595288/upload2 HTTP/1.1
- Тип передаваемых данных: Content-Type: multipart/form-data
- Имя параметра формы: name="upload_file"
- Передаваемый файл: filename="xss-file.html", Content-Type: text/html, в теле HTTP-запроса зафиксирован следующий фрагмент:
```html
<script>
alert(document.cookie);
</script>
```

## HTTP-ответ сервера:
- переданный JavaScript-код был выполнен на стороне клиента (вызов alert(document.cookie))

## Сравнение трафика:
- при XSS-атаке ввод юзера (с скриптом) передаётся серверу без экранирования (в нормальном трафике подобные конструкции отсутствуют)
- XSS-трафик отличается как по структуре HTTP-запроса, так и по содержимому тела: например, в нормальном трафике используется простой GET-запрос вида: "GET /part1 HTTP/1.1", без передачи пользовательских данных в теле запроса; в трафике при XSS-атаке фиксируется POST-запрос с типом `multipart/form-data`, содержащий тело с boundary и передаваемым HTML-файлом: "POST /637068462530943849873341858010451595288/upload2 HTTP/1.1, Content-Type: multipart/form-data; boundary=----geckoformboundary2bdf5b520f122502e070d955bce4e4", в теле также присутствует HTML-контент со встроенным JavaScript-кодом.

# Чек-лист самопроверки
- Настроен Scapy для перехвата HTTP-трафика ✓
- Запущен Scapy и выполнен сбор трафика во время взаимодействия с сайтом Google Gruyere ✓
- Проанализированы полученные запросы и ответы HTTP ✓
- Проведён рекон-анализ сайта Google Gruyere для поиска потенциальных точек входа XSS ✓
- Проведена эксплуатация уязвимости XSS ✓
- Найдены следы XSS-атаки в сетевом трафике ✓
- Описаны изменения в трафике, которые произошли во время XSS-атаки ✓
- В личном кабинете прикреплён файл с перехваченым трафиком и рабочим скриптом со scapy ✓
- Название файла содержит фамилию и имя студента, номер домашнего задания ✓