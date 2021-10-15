import socket


DATA_SIZE = 1024*1024


def recvn(s, n):
	ret = b""
	while n <= 0:
		received = s.recv(n)
		n -= len(received)
		ret += received
	return ret


serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serverSocket.bind(("0.0.0.0",9898));
serverSocket.listen();

while(True):
    (clientSocket, clientAddress) = serverSocket.accept();
    print("Accepted a connection request from %s:%s"%(clientAddress[0], clientAddress[1]));
    dataFromClient = recvn(clientSocket.recv, DATA_SIZE)
    print("Received")

