import argparse
import os
import json
import requests
import smtplib
import pandas as pd
import matplotlib.pyplot as plt
from dotenv import load_dotenv
from email.message import EmailMessage
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
SURICATA_LOG = BASE_DIR / "logs" / "eve.json"
OUTPUT_DIR = BASE_DIR / "output"
REPORT_PATH = OUTPUT_DIR / "report.csv"
PLOT_PATH = OUTPUT_DIR / "top_ips.png"


def load_suricata_alerts(log_path: Path) -> pd.DataFrame:
    """
    Загружает Suricata eve.json и оставляет только alert-события.
    Возвращает DataFrame с основными полями.
    """
    rows = []

    if not log_path.exists():
        print(f"[ERR] Файл логов не найден: {log_path}")
        return pd.DataFrame()

    with log_path.open("r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()

            if not line:
                continue

            try:
                event = json.loads(line)
            except json.JSONDecodeError as e:
                print(f"[WARN] Ошибка загрузки JSON: {e}")
                continue

            if event.get("event_type") != "alert":
                continue

            alert_info = event.get("alert", {})
            rows.append({
                "timestamp": event.get("timestamp"),
                "src_ip": event.get("src_ip"),
                "src_port": event.get("src_port"),
                "dest_ip": event.get("dest_ip"),
                "dest_port": event.get("dest_port"),
                "proto": event.get("proto"),
                "alert_signature": alert_info.get("signature"),
                "alert_category": alert_info.get("category"),
                "severity": alert_info.get("severity"),
            })

    return pd.DataFrame(rows)


def filter_high_severity(alerts_df: pd.DataFrame, max_severity: int = 2) -> pd.DataFrame:
    """
    Оставляет только события с severity <= max_severity.
    """
    if alerts_df.empty or "severity" not in alerts_df.columns:
        return alerts_df

    filtered_df = alerts_df.copy()
    filtered_df["severity"] = pd.to_numeric(filtered_df["severity"], errors="coerce")
    filtered_df = filtered_df[filtered_df["severity"] <= max_severity]

    return filtered_df


def extract_unique_ips(df: pd.DataFrame) -> list:
    """
    Извлекает уникальные IP из src_ip и dest_ip.
    """
    ips = set()

    if "src_ip" in df.columns:
        ips.update(df["src_ip"].dropna().astype(str).tolist())

    if "dest_ip" in df.columns:
        ips.update(df["dest_ip"].dropna().astype(str).tolist())

    return sorted(ips)


def check_ip_virustotal(ip: str, api_key: str) -> dict:
    """
    Проверяет IP через VirusTotal API v3.
    Возвращает словарь с результатом.
    """
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": api_key}

    try:
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        data = response.json()
        stats = (
            data.get("data", {})
                .get("attributes", {})
                .get("last_analysis_stats", {})
        )

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)

        return {
            "ip": ip,
            "vt_found": True,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "threat_detected": malicious > 0 or suspicious > 0
        }

    except requests.RequestException as e:
        print(f"[WARN] Ошибка проверки IP {ip}: {e}")
        return {
            "ip": ip,
            "vt_found": False,
            "malicious": None,
            "suspicious": None,
            "harmless": None,
            "undetected": None,
            "threat_detected": False
        }


def simulate_response(vt_results: list) -> None:
    """
    Имитация реагирования: печатает сообщение о блокировке IP.
    """
    threats = [result for result in vt_results if result["threat_detected"]]

    if not threats:
        print("[INFO] Угроз по результатам VirusTotal не найдено.")
        return

    lines = []

    for threat in threats:
        line = (
            f"[BLOCK] IP {threat['ip']} помечен как подозрительный. "
            f"Malicious={threat['malicious']}, Suspicious={threat['suspicious']}"
        )

        print(line)
        lines.append(line)

    send_email_notification(
        subject="Threat monitoring alert",
        body="\n".join(lines)
    )


def send_email_notification(subject: str, body: str) -> None:
    """
    Отправка уведомления на email.
    """
    smtp_host = os.getenv("SMTP_HOST")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER")
    smtp_password = os.getenv("SMTP_PASSWORD")
    sender = os.getenv("EMAIL_SENDER")
    recipient = os.getenv("EMAIL_RECIPIENT")

    if not all([smtp_host, smtp_port, smtp_user, smtp_password, sender, recipient]):
        print("[WARN] Email-настройки не заданы. Почтовое уведомление пропущено.")
        return

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = recipient
    msg.set_content(body)

    try:
        with smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=30) as server:
            server.login(smtp_user, smtp_password)
            server.send_message(msg)
        print(f"[OK] Email-уведомление отправлено на {recipient}")
    except Exception as e:
        print(f"[WARN] Не удалось отправить email: {e}")


def build_report(alerts_df: pd.DataFrame, vt_results: list) -> pd.DataFrame:
    """
    Объединяет данные из логов и VirusTotal в единый отчёт по src_ip.
    """
    if alerts_df.empty:
        return pd.DataFrame()

    src_counts = (alerts_df["src_ip"].value_counts().reset_index())
    src_counts.columns = ["ip", "alert_count"]

    if not vt_results:
        src_counts["vt_found"] = False
        src_counts["malicious"] = None
        src_counts["suspicious"] = None
        src_counts["harmless"] = None
        src_counts["undetected"] = None
        src_counts["threat_detected"] = False

        return src_counts

    vt_df = pd.DataFrame(vt_results)
    report_df = src_counts.merge(vt_df, on="ip", how="left")
    report_df["vt_found"] = report_df["vt_found"].fillna(False)
    report_df["threat_detected"] = report_df["threat_detected"].fillna(False)

    return report_df


def save_report(report_df: pd.DataFrame, path: Path) -> None:
    """
    Сохраняет отчёт в CSV.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    report_df.to_csv(path, index=False, sep=";", encoding="utf-8-sig")
    print(f"[OK] Отчёт сохранён в CSV-файл: {path}")


def save_plot(alerts_df: pd.DataFrame, path: Path) -> None:
    """
    Строит график "Топ-5 IP по кол-ву alert-событий" и сохраняет в PNG.
    """
    path.parent.mkdir(parents=True, exist_ok=True)

    if alerts_df.empty:
        print("[WARN] Нет данных для построения графика.")
        return

    top_ips = alerts_df["src_ip"].value_counts().head(5)

    plt.figure(figsize=(10, 5))
    top_ips.plot(kind="bar")
    plt.title("Топ-5 IP по кол-ву alert-событий (Suricata)")
    plt.xlabel("IP-адрес")
    plt.ylabel("Кол-во alert-событий")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig(path, dpi=150)
    plt.close()

    print(f"[OK] График сохранён в PNG-файл: {path}")


def main(vt_api_key: str | None, max_severity: int):
    print('_' * 30)
    print("\nМониторинг и реагирование на угрозы")
    print('_' * 30, '\n')

    alerts_df = load_suricata_alerts(SURICATA_LOG)

    if alerts_df.empty:
        print("[ERR] Нет alert-событий для анализа.")
        return

    print(f"[INFO] Загружено alert-событий: {len(alerts_df)}")

    alerts_df = filter_high_severity(alerts_df, max_severity=max_severity)

    if alerts_df.empty:
        print("[ERR] После фильтрации по severity не осталось событий для анализа.")
        return
    
    print(f"[INFO] После фильтрации по severity <= {max_severity} осталось событий: {len(alerts_df)}")

    unique_ips = extract_unique_ips(alerts_df)
    print(f"[INFO] Найдено уникальных IP для проверки: {len(unique_ips)}")

    vt_results = []

    if vt_api_key:
        for ip in unique_ips[:10]:
            result = check_ip_virustotal(ip, vt_api_key)
            vt_results.append(result)
    else:
        print("[WARN] VT_API_KEY не задан. Проверка через VirusTotal пропущена.")

    simulate_response(vt_results)

    report_df = build_report(alerts_df, vt_results)

    if not report_df.empty:
        save_report(report_df, REPORT_PATH)
    else:
        print("[WARN] Отчёт не был сформирован.")

    save_plot(alerts_df, PLOT_PATH)


def parse_args() -> argparse.Namespace:
    """
    Обрабатывает аргументы командной строки.
    """
    parser = argparse.ArgumentParser(
        description="Автоматизированный мониторинг и реагирование на угрозы"
    )
    parser.add_argument(
        "--max-severity",
        type=int,
        default=2,
        help="Максимальный уровень severity для анализа (по умолчанию: 2)"
    )

    args = parser.parse_args()

    if args.max_severity < 1 or args.max_severity > 4:
        parser.error("--max-severity должен быть в диапазоне от 1 до 4")

    return args


if __name__ == "__main__":
    load_dotenv(BASE_DIR / ".env")
    args = parse_args()
    vt_api_key = os.getenv("VT_API_KEY")
    main(vt_api_key, args.max_severity)