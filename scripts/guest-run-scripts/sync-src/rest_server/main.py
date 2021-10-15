import sys
from rest_service import start_rest_service


HOST = "0.0.0.0"
PORT = 5000


def main():
    host = HOST
    if "-host" in sys.argv:
        host = int(sys.argv[sys.argv.index("-host") + 1])
    start_rest_service(host=host, port=PORT)
    print("Goodbye!")


if __name__ == '__main__':
    main()
