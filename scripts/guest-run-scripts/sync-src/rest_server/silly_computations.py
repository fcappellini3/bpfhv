import random


def fibonacci(n: int):
    if n == 0:
        return 0
    if n == 1:
        return 1
    return fibonacci(n-2) + fibonacci(n-1)


def random_stream(size: int):
    computed = 0
    while computed < size:
        r = random.randint(0, 100)
        for i in range(8):
            yield r + i
            computed += 1
            if computed >= size:
                break


def wordcount(text: str):
    for unwanted in (".", ",", ";", "(", ")", "\r", "\n"):
        text.replace(unwanted, "")
    word_list = text.split(" ")
    word_list = (word for word in word_list if word not in ("", " "))
    ret = {}
    for word in word_list:
        if word not in ret:
            ret[word] = 0
        ret[word] = ret[word] + 1
    return ret
