from Python_HW07_Task1 import fetch_posts
from Python_HW07_Task2 import fetch_weather

def check_task1():
    posts = fetch_posts()

    assert len(posts) >= 5

    for post in posts[:5]:
        assert "title" in post
        assert "body" in post

    print("Задание 1 выполнено ✓")


def check_task2():
    data = fetch_weather("Москва")

    assert "main" in data and "temp" in data["main"]
    assert "weather" in data and len(data["weather"]) > 0

    print("Задание 2 выполнено ✓")


if __name__ == "__main__":
    check_task1()
    check_task2()
