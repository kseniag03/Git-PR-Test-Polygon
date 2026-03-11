import requests
import os
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("OPENWEATHER_API_KEY")
BASE_URL = "https://api.openweathermap.org/data/2.5/weather"


def fetch_weather(city):
    params = {
        "q": city,
        "appid": API_KEY,
        "units": "metric",
        "lang": "ru"
    }

    response = requests.get(BASE_URL, params=params)
    response.raise_for_status()

    return response.json()


def print_weather(data, city):
    temperature = data["main"]["temp"]
    description = data["weather"][0]["description"]

    print(f"Город: {city}")
    print(f"Температура: {temperature}°C")
    print(f"Погода: {description}")


if __name__ == "__main__":
    if not API_KEY:
        raise RuntimeError("API ключ не найден. Проверьте файл .env")

    city = input("Введите название города: ")
    print_weather(fetch_weather(city), city)
