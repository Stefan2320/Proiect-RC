import socket
import sys
import select
import threading
import json

#mai intai ack si dupa pachet


def string2bits(s):
    return [bin(ord(x))[2:].zfill(8) for x in s]

def bits2string(b):
    return ''.join([chr(int(x, 2)) for x in b])
#version,type,token length
def first_byte():
    byte=""
    #VERSION
    version="01"
    byte += version
    # Type: CON (00), NON (01), ACK (10), RES (11)
    byte+=Request_Type
    #TOKEN LENGTH
    token_length = "0100"

    byte+=token_length
    return byte
#code
def second_byte():
    #Code: Succes.content
    byte="01000101"
    return byte
#third and fourth byte
def message_ID():
   return messageID
def get_token():
    return token
def delimitation_byte():
    byte = "11111111"
    return byte

def package(message1 =None,content1 = None):
    if message1!=None:
        message = message1
    else:
        message="ceva"
    if content1!=None:
        action = content1
    else:
        action="altceva"

    request = {
        "content":message,
         "string":action
    }
    request_json = json.dumps(request)
    return string2bits(request_json)
def create_header(message =None,content = None):
    header=""
    """
    print("fb",first_byte())
    print(second_byte())
    print(message_ID())
    print(get_token())
    print(delimitation_byte())
    """

    header+=first_byte()+second_byte()+message_ID()+get_token()+delimitation_byte()
    for o in package(message,content):
        header+=o
    return header
def verificare_parola(username,password):
    #deschidere fisier care contine usernames si parole lista[i] username=parola
    db = open('usernames.txt', 'r')
    db2= open('usernames.txt','a')
    lista = db.readlines()
    user_found = False
    print(len(lista))
    for i in range(len(lista)):
        user, pas = lista[i].split("=")
        for i in range(len(pas)):
            if pas[i] == "\n":
               pas=pas.replace('\n','')

        if user == username:
            if pas == password:
                acces1 = True
            else:
                acces1 = False
            user_found = True
    if user_found == False:
        acces1 = True
        db2.write(username+"="+password+'\n')

    if acces1 == True:
        print("Acces granted!")
    else:
        print("Intruder alert!")
    return acces1
def receive_fct():
    global running
    contor = 0
    while running:
        # Apelam la functia sistem IO -select- pentru a verifca daca socket-ul are date in bufferul de receptie
        # Stabilim un timeout de 1 secunda
        r, _, _ = select.select([s], [], [], 1)
        if not r:
            contor = contor + 1
        else:
            #sunt date in buffer
            dataFromClient, address = s.recvfrom(1024)
            requestFromClient_string = dataFromClient.decode('utf-8')
            #primii octeti o sa fie 8 octeti
            primii_octeti = string2bits(requestFromClient_string[0:8])
            #in CoApVs_Type_TokenLen o sa avem CoAp version,Type si Token Length
            CoApVs_Type_TokenLen = primii_octeti[0]
            token_length = int(CoApVs_Type_TokenLen[4] + CoApVs_Type_TokenLen[5] + CoApVs_Type_TokenLen[6] + CoApVs_Type_TokenLen[7], 2)
            CoAp_Version= CoApVs_Type_TokenLen[0] + CoApVs_Type_TokenLen[1]
            global Request_Type
            Request_Type = CoApVs_Type_TokenLen[2] + CoApVs_Type_TokenLen[3]
            inceput_payload = 4 + 1 + token_length  # 4 octeti + octetul cu "11111111" + nr_octeti_token
            Code = primii_octeti[1]
            global messageID
            messageID = primii_octeti[2] + primii_octeti[3]
            global token
            token = ""
            for j in range(4, 4 + token_length):
                token += primii_octeti[j]
            payload = json.loads(requestFromClient_string[inceput_payload:])
            print("CoAP Version: " + CoAp_Version)  # primii 2 biti
            print("Request Type: " + Request_Type)  # urmatorii 2 biti
            print("Token Length: " + str(token_length))
            print("Request/Response Code: " + Code)
            print("Message ID: " + str(int(messageID, 2)))
            print("Token: " + token)
            command = payload["command"]
            parameters = payload["parameters"]
            username = payload["username"]
            timestamp = payload["timestamp"]
            password = payload["password"]
            print("\n\nReceived message:")
            print("Command: " + command, parameters)
            print("Timestamp: " + timestamp)
            print("From: "+username)
            print("Adress: ", address)
            #daca acces e False se va trimite o alerta spre client!
            acces=verificare_parola(username,password)
            send_data(acces)


def send_data(acces):
    global Request_Type
    if acces == True:
        if Request_Type == "00":
            random=0
            if random == 0:
                Request_Type = "10"
                # content-ul va fi gol
                message = create_header("ACK"," ")
                s.sendto(bytes(message, encoding="utf-8"), (dip, int(dport)))
                Request_Type = "00"
                # aici va fi contentul
                message1 = create_header("content1","content2")
                s.sendto(bytes(message1, encoding="utf-8"), (dip, int(dport)))
            else:
                Request_Type= "10"
                # va fi ack + content
                message = create_header("conten1","content2")
                s.sendto(bytes(message, encoding="utf-8"), (dip, int(dport)))
    else:
        s.sendto(bytes("acces denied",encoding="utf-8"),(dip, int(dport)))

# Citire nr port din linia de comanda
if len(sys.argv) != 4:
    print("help : ")
    print("  --sport=numarul_meu_de_port ")
    print("  --dport=numarul_de_port_al_peer-ului ")
    print("  --dip=ip-ul_peer-ului ")
    sys.exit()

for arg in sys.argv:
    if arg.startswith("--sport"):
        temp, sport = arg.split("=")
    elif arg.startswith("--dport"):
        temp, dport = arg.split("=")
    elif arg.startswith("--dip"):
        temp, dip = arg.split("=")

# Creare socket UDP
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

s.bind(('0.0.0.0', int(sport)))

running = True

try:
    receive_thread = threading.Thread(target=receive_fct)
    receive_thread.start()
except:
    print("Eroare la pornirea thread‐ului")
    sys.exit()
"""
while True:
    try:
        #data = input("Trimite: ")
       #s.sendto(bytes(data, encoding="ascii"), (dip, int(dport)))

    except KeyboardInterrupt:
        running = False
        print("Waiting for the thread to close...")
        receive_thread.join()
        break

"""
