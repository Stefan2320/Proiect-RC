import json
import datetime
import random

from functions import *


def createHeader(username, passwd, request_type, interfaceObj):
    # creating the entire header
    firstByte = header_FirstByte(interfaceObj.input_box_msgType.currentText())
    secondByte = header_SecondByte(request_type)
    msgID = header_MessageID()
    token = header_Token(interfaceObj.input_box_msgType.currentText())
    separatingByte = header_SeparatingByte()
    payload = header_Payload(username, passwd, request_type, interfaceObj)

    header = []
    header.append(firstByte)
    header.append(secondByte)
    for octet in msgID:
        header.append(octet)
    for octet in token:
        header.append(octet)
    header.append(separatingByte)
    for octet in payload:
        header.append(octet)

    print(header)
    # In acest moment avem header-ul complet (este o lista de stringuri, fiecare string reprezentand un sir de 8 "biti"
    # Vom transforma fiecare string intr-un caracter corespunzator

    header_string = bits2string(header)

    return header_string


def header_FirstByte(boxValue):
    # --------------- first-byte --------------- #
    # VER: 01
    octet1 = "01"

    # Type: CON (00), NON (01), ACK (10), RES (11)
    if boxValue == "Confirmable":
        octet1 += "00"
    elif boxValue == "Non-confirmable":
        octet1 += "01"

    # Token Length
    tokenLength = 4  # must be between (0-8) #HIGH SECURITY - 8,  LOW SECURITY - 2
    octet1 += decimalToBinaryString(tokenLength, 4)

    return octet1

def header_SecondByte(comanda):
    # -------------- second-byte ---------------- #
    # Request/Response Code
    if comanda.count(' ') >= 1:
        tipComanda = comanda.split(' ')[0]
    else:
        tipComanda = comanda

    print(tipComanda)
    print(comanda)
    octet2 = ""

    if comanda == "":
        octet2 = "00000000" # EMPTY
    elif tipComanda == "run":
        octet2 = "00010101" # RUN
    elif tipComanda == "cd" or tipComanda == "ls" or tipComanda == "copy" or tipComanda == "readText" or tipComanda == "pwd":
        octet2 = "00000001" # GET
    elif tipComanda == "paste" or tipComanda == "newFile" or tipComanda == "newDir" or tipComanda == "write" or tipComanda == "append":
        octet2 = "00000010" # POST
    elif tipComanda == "rm":
        octet2 = "00000100" # DELETE
    elif tipComanda == "register":
        octet2 = "00010110" # REGISTER
    elif tipComanda == "msg":
        octet2 = "00010111" # MESSAGE
    # Method code 0.22 : register
    # Method code 0.23 : msg

    return octet2

messageID = 0

def header_MessageID():
    # --------------- message-id ----------------- #
    global messageID
    messageID = increment16bits(messageID)
    messageID_string = decimalToBinaryString(messageID, 16)  # e pe 16 biti
    messageID_octet1 = messageID_string[0:8]
    messageID_octet2 = messageID_string[8:16]

    return [messageID_octet1, messageID_octet2]

def header_Token(boxValue):
    # --------------- token ---------------------- #
    token = []
    octet1 = header_FirstByte(boxValue)
    tokenLength = int(octet1[4] + octet1[5] + octet1[6] + octet1[7], 2)
    # este impartit pe octeti (este generat random -> rol in securitatea comunicatiei)
    for i in range(tokenLength):
        token_octet = ""
        for j in range(8):
            token_octet += str(random.choice([0, 1]))
        token.append(token_octet)

    return token


def header_SeparatingByte():
    # --------------- biti delimitare payload ----------------- #
    biti_delimitare = "11111111"

    return biti_delimitare

def header_Payload(username, passwd, request_type, interfaceObj):
    # --------------- payload -------------------- #

    if request_type.count('-') >= 1:
        command, parameters = request_type.split("-", 1)
        parameters.replace(" ", "")
        parameters = "-" + parameters
    elif request_type.count(' ') >= 1:
        command, parameters = request_type.split(" ", 1)
        parameters.replace(" ", "")
    else:
        command = request_type
        parameters = "None"
    command.replace(" ", "")

    if command == 'write' or command == 'append':
        parameters += " " + interfaceObj.plainTextEdit.toPlainText()
    elif command == 'msg':
        parameters = interfaceObj.plainTextEdit.toPlainText()

    request = {
        "username": username,
        "password": passwd,
        "command": command,  # ls, dir
        "parameters": parameters,  # -l, -r
        "timestamp": str(datetime.datetime.now())
    }

    # converting to JSON:
    request_json = json.dumps(request)

    return string2bits(request_json)