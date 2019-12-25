import random
import socket
from DH_protocol import DH_Endpoint

HOST = '127.0.0.1'
PORT = 8082

sock = socket.socket()
sock.bind((HOST, PORT))
sock.listen(1)
conn, addr = sock.accept()
print(f'Listen {PORT} port...')

def make_keys(conn):
    """
    Функция создания объекта сервера с протоколом шифрования Diffie-Hellman
    :param conn:
    :return: serverDH:
    """
    # получаем публичные ключи от клиента
    bunch = conn.recv(2054).decode()
    bunch = bunch.split(' ')
    # создаем сервера со связкой ключей: публичные от клиента и рандомный персональный
    serverDH = DH_Endpoint(int(bunch[0]), int(bunch[1]), random.randint(1, 320))
    return serverDH

def access_check(client_public_key):
    """
    Функция проверки наличия публичного ключа клиента в списке разрешенных
    :param client_public_key:
    :return: bool flag:
    """
    with open('Keys', 'r') as file:
        flag = False
        for line in file:
            if int(line) == client_public_key:
                flag = True
                break
    return flag

serverDH = make_keys(conn)

if access_check(serverDH.client_public_key):
    conn.send("Access is allowed".encode())

    #отправляем частичный ключ сервера (B) клиенту
    server_partial_key = serverDH.generate_partial_key()
    conn.send(str(server_partial_key).encode())

    #получаем частичный ключ от клиента
    client_key_partial = int(conn.recv(1024).decode())
    print(client_key_partial)

    #создаем полный ключ
    serverDH.generate_full_key(client_key_partial)


    while True:

        #принимаем сообщение от клиента и раскодируем его
        msg = conn.recv(2024).decode()
        print(f'Encrypt messege: {msg} \nDecrypt messege: {serverDH.decrypt_message(msg)}\n')
        if serverDH.decrypt_message(msg) == 'Exit' or serverDH.decrypt_message(msg) == 'exit':
            break

    conn.close()

else:
    conn.close()
