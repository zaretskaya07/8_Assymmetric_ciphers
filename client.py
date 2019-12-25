import socket
from DH_protocol import DH_Endpoint

HOST = '127.0.0.1'
PORT = 8082

sock = socket.socket()
sock.connect((HOST, PORT))

#g-client_public_key
#p-server_public_key

#создаем клиента по протоколу DH
clientDH = DH_Endpoint()
#создаем связку публичных ключей клиента и сервера и персональный ключ клиента
clientDH.bunch_of_public_keys()

keys = str(clientDH.client_public_key)+' '+str(clientDH.server_public_key)
#отправляем серверу публичные ключи
sock.send(keys.encode())


msg = sock.recv(1024).decode()
if msg == "Access is allowed":
    print(msg+"\nTo exit, send \"exit\"")

    # получаем частичный ключ от сервера
    server_key_partial = int(sock.recv(1024).decode())
    # print(server_key_partial)


    client_partial_key = clientDH.generate_partial_key()
    sock.send(str(client_partial_key).encode())  # отправляем частичный ключ клиента (А) серверу

    # восстанавливаем полный ключ
    clientDH.generate_full_key(server_key_partial)

    while True:
        msg = input(""">>""")
        if msg == 'exit' or msg == 'Exit':
            sock.send(clientDH.encrypt_message(msg).encode())
            break
        # отправляем закодированное сообщение
        sock.send(clientDH.encrypt_message(msg).encode())


    sock.close()

else:
    print("Access not allowed")
    sock.close()
