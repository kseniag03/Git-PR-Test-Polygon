import requests

BASE_URL = "https://jsonplaceholder.typicode.com/posts"

def fetch_posts():
    response = requests.get(BASE_URL)
    response.raise_for_status()

    return response.json()

def print_first_posts(posts):
    for post in posts[:5]:
        print("Заголовок:")
        print(post["title"])
        print("Тело:")
        print(post["body"])
        print("_" * 50)
        print()


if __name__ == "__main__":
    print_first_posts(fetch_posts())
