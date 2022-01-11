import select
import socket
import sys, threading

running = False
s = None

def receive_fct():
    global running, s
    contor = 0
    while running:
        # Apelam la functia sistem IO -select- pentru a verifca daca socket-ul are date in bufferul de receptie
        # Stabilim un timeout de 1 secunda
        if s != None:
            r, _, _ = select.select([s], [], [], 1)
            if not r:
                contor = contor + 1
            else:
                data, address = s.recvfrom(1024)
                print("S-a receptionat ", str(data.decode('latin-1')), " de la ", address)
                print("Contor = ", contor)

#Receive Thread
def threadInit():
    try:
        receive_thread = threading.Thread(target=receive_fct)
        receive_thread.start()
    except:
        print("Eroare la pornirea thread‐ului")
        sys.exit()

# Creare socket UDP
def create_socket(sport):
    global running, s

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.bind(('0.0.0.0', int(sport)))
    running = True
    threadInit()