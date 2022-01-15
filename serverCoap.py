import socket
import sys
import select
import threading
import json
import os
import shutil
from subprocess import Popen

#mai intai ack si dupa pachet
global payload
global Request_Type
global Code
global messageID
global token
global inceput_payload
global succesByte
global currentDirectory

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
    global succesByte
    return succesByte


#third and fourth byte
def message_ID():
   return messageID

def get_token():
    return token

def delimitation_byte():
    byte = "11111111"
    return byte

def ls():
    print(os.getcwd())
    files_folders = [f for f in os.listdir(os.getcwd())]
    return files_folders

def pwd():
    return os.getcwd()

def createFile(fileName):
    f = open(os.getcwd() + '\\' + fileName, "x")

def createFolder(folderName):
    os.mkdir(os.getcwd() + '\\' + folderName)


def changeDirectory(param):
    # daca nu sunt deja in fisierul Root atunci ma mut inapoi
    if param == '..':
        if os.getcwd() != (original_path + '\\Root'):
            os.chdir('..')
        else:
            raise Exception('You are already in the Root')
    else:
        path = os.getcwd() + '/' + param
        if os.path.isdir(path):
            os.chdir(path)
            print(os.getcwd())
        else:
            raise Exception('This is not a folder')

def readText(param):
    data = ""
    for root, dirs, files in os.walk(path):
        if param in files:
            text_file = open(param, "r")
            # read whole file to a string
            data = text_file.read()
            data = data.replace('\\n', '\n').replace('\\t', '\t')
            print(data)
            # close file
            text_file.close()
            return data
        else:
            raise Exception('File does not exist, check spelling!')

def remove(param):
    for root, dirs, files in os.walk(path):
        print(dirs)
        if param in files:
            cale = os.getcwd() + "\\" + param
            os.remove(cale)
        elif param in dirs:
            cale = os.getcwd() + "\\" + param
            shutil.rmtree(cale)
        else:
            raise Exception('File not found!')


def append(param):
    split_param = param.split(" ",1)
    file_name = split_param[0]
    message = split_param[1]
    for root, dirs, files in os.walk(path):
        if file_name in files:
            f = open(file_name, "a")
            f.write(message)
            f.close()
        else:
            raise Exception('Can not append!')

def write(param):
    split_param = param.split(" ",1)
    file_name = split_param[0]
    message = split_param[1]
    for root, dirs, files in os.walk(path):
        if file_name in files:
            f = open(file_name, "r+")
            f.truncate(0)
            f.write(message)
            f.close()
        else:
            raise Exception('Can not write!')

def run(param):
    type = param[-4:]
    print(type)
    good = False
    for root, dirs, files in os.walk(path):
        if param in files:
            if type == '.bat':
                good = True
                os.chdir(path)
                os.startfile(param)
        else:
            if good == False:
                print(good)
                raise Exception('Can not run!')

def create_payload():
    global payload
    global Code
    global succesByte

    command = payload['command']
    parameters = payload['parameters']
    print(parameters)
    content = []
    print("Code: ", Code)
    print(command)
    error = ''
    if Code.replace(" ", "") == '00000001' and command.replace(" ", "") == 'ls':
        try:
            content = ls()
            succesByte = '01000001'
        except Exception as e:
            # 10000001 - Server error response, eroare
            succesByte = '10000001'
            print(str(e))
            error = str(e)


    if Code.replace(" ", "") == '00000010' and command.replace(" ", "") == 'newFile':
        try:
            createFile(parameters)
            # 01000010 va insemna 'Fisier creat cu succes'
            succesByte = '01000010'
        except Exception as e:
            # 10000010 - Server error response, va insemna 'Fisierul deja exista'
            succesByte = '10000010'
            print(str(e))
            error = str(e)

    if Code.replace(" ", "") == '00000001' and command.replace(" ", "") == 'pwd':
        try:
            content = pwd()
            # 01000001 inseamna succes
            succesByte = '01000001'
        except Exception as e:
            # 10000001 - Server error response, eroare
            succesByte = '10000001'
            print(str(e))
            error = str(e)

    if Code.replace(" ", "") == '00000010' and command.replace(" ", "") == 'newDir':
        try:
            createFolder(parameters)
            # 01000010
            succesByte = '01000010'
        except Exception as e:
            # 10000001 - Server error response, eroare la creare fisier
            succesByte = '10000010'
            print(str(e))
            error = str(e)

    if Code.replace(" ", "") == '00000001' and command.replace(" ", "") == 'cd':
        try:
            changeDirectory(parameters)
            # 01000010
            succesByte = '01000001'
        except Exception as e:
            # 10000001 - Server error response, eroare la creare fisier
            succesByte = '10000001'
            print(str(e))
            error = str(e)

    if Code.replace(" ","") == '00000001' and command.replace(" ","") == 'readText':
        try:
            content = readText(parameters)
            succesByte = '01000001'
        except Exception as e:
            succesByte = '10000001'
            print(str(e))
            error = str(e)

    if Code.replace(" ","") == '00000100' and command.replace(" ","") == 'rm':
        try:
            remove(parameters)
            succesByte = '01000100'
        except Exception as e:
            succesByte = '10000100'
            print(str(e))
            error = str(e)

    if Code.replace(" ", "") == '00000010' and command.replace(" ", "") == 'append':
        try:
            append(parameters)
            succesByte = '01000010'
        except Exception as e:
            succesByte = '10000010'
            print(str(e))
            error = str(e)

    if Code.replace(" ", "") == '00000010' and command.replace(" ", "") == 'write':
        try:
            write(parameters)
            succesByte = '01000010'
        except Exception as e:
            succesByte = '10000010'
            print(str(e))
            error = str(e)


    if Code.replace(" ", "") == '00010101' and command.replace(" ", "") == 'run':
        try:
            run(parameters)
            succesByte = '01010101'
        except Exception as e:
            succesByte = '10010101'
            print(str(e))
            error = str(e)

    payload ={
        'content' : content,
        'error' : error,
        'command' : command.replace(" ", "")
    }

    payload_json = json.dumps(payload)
    print(payload_json)
    return string2bits(payload_json)

# returneaza headerul
def create_header():
    header=[]
    """
    print("fb",first_byte())
    print(second_byte())
    print(message_ID())
    print(get_token())
    print(delimitation_byte())
    """
    payload = create_payload()
    header.append(first_byte())
    header.append(second_byte())
    header.append(message_ID())
    header.append(get_token())
    header.append(delimitation_byte())
    for o in payload:
        header.append(o)


    return header

def verificare_parola(username,password):
    #deschidere fisier care contine usernames si parole lista[i] username=parola
    db = open(original_path + '\\usernames.txt', 'r')
    db2= open(original_path + '\\usernames.txt','a')
    lista = db.readlines()
    global succesByte
    global Code
    if Code == '00010110': # codul 00010110 este pentru inregistrare
        acces = True
        succesByte = '01010110'
        db2.write(username+"="+password+'\n')
    else:
        j = 0
        acces = False
        while j < len(lista) and acces == False:
            user, pas = lista[j].split("=")
            for i in range(len(pas)):
                if pas[i] == "\n":
                   pas=pas.replace('\n','')
            if user == username and pas == password:
                acces = True
            j = j + 1

    if acces == True:
        print("Acces granted!")
    else:
        print("Intruder alert!")
    return acces

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
            requestFromClient_string = dataFromClient.decode('latin-1')
            #primii octeti o sa fie 8 octeti
            primii_octeti = string2bits(requestFromClient_string[0:8])
            #in CoApVs_Type_TokenLen o sa avem CoAp version,Type si Token Length
            CoApVs_Type_TokenLen = primii_octeti[0]
            token_length = int(CoApVs_Type_TokenLen[4] + CoApVs_Type_TokenLen[5] + CoApVs_Type_TokenLen[6] + CoApVs_Type_TokenLen[7], 2)
            CoAp_Version= CoApVs_Type_TokenLen[0] + CoApVs_Type_TokenLen[1]
            global Request_Type
            Request_Type = CoApVs_Type_TokenLen[2] + CoApVs_Type_TokenLen[3]
            global inceput_payload
            inceput_payload = 4 + 1 + token_length  # 4 octeti + octetul cu "11111111" + nr_octeti_token
            global Code
            Code = primii_octeti[1]
            global messageID
            messageID = primii_octeti[2] + primii_octeti[3]
            global token
            token = ""
            for j in range(4, 4 + token_length):
                token += primii_octeti[j]
            global payload
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
        # if Request_Type == "00":
        #     random=0
        #     if random == 0:
        #         Request_Type = "10"
        #         # content-ul va fi gol
        #         message = create_header("ACK"," ")
        #         s.sendto(bytes(message, encoding="latin-1"), (dip, int(dport)))
        #         Request_Type = "00"
        #         # aici va fi contentul
        #         message1 = create_header("content1","content2")
        #         s.sendto(bytes(message1, encoding="latin-1"), (dip, int(dport)))
        #     else:
        #         Request_Type= "10"
        #         # va fi ack + content
        #         message = create_header("conten1","content2")
        #         s.sendto(bytes(message, encoding="latin-1"), (dip, int(dport)))
        message = create_header()
        print("Mesaj: ",message)
        s.sendto(bytes(str(message), encoding="latin-1"), (dip, int(dport)))
    else:
        s.sendto(bytes("Acces denied",encoding="latin-1"), (dip, int(dport)))

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
original_path = os.getcwd()
path = os.getcwd() + '\\Root'
os.chdir(path)

try:
    receive_thread = threading.Thread(target=receive_fct)
    receive_thread.start()
except:
    print("Eroare la pornirea thread‐ului")
    sys.exit()

'''
while True:
    try:
        data = input("Trimite: ")
        s.sendto(bytes(data, encoding="ascii"), (dip, int(dport)))

    except KeyboardInterrupt:
        running = False
        print("Waiting for the thread to close...")
        receive_thread.join()
        break
'''


