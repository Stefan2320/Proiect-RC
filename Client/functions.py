from PyQt5 import QtGui, QtCore

def decimalToBinaryString(number,nbits):
    straux = str(bin(number))[2:]
    return (nbits - len(straux)) * "0" + straux

def increment16bits(s):
    if s == pow(2,16) -1:
        s = 0
    else:
        s = s + 1
    return s

def string2bits(s):
    return [bin(ord(x))[2:].zfill(8) for x in s]

def bits2string(b):
    return ''.join([chr(int(x, 2)) for x in b])

def isValidIP(ip):
    validFormat = True
    if ip.count('.') != 3:
        validFormat = False
    if validFormat == True:
        validFormat = ip.split('.')
        for i in range(4):
            if int(validFormat[i]) < 0 or int(validFormat[i]) > 255:
                validFormat = False
    return validFormat

def isValidPort(port):
    if int(port) < 1024 or int(port) > 65353:
        return False
    return True

def isValidCommand(command):
    if len(command) == 0:
        return False
    return True

def palette_theme():
    palette = QtGui.QPalette()
    palette.setColor(QtGui.QPalette.Window, QtGui.QColor(207, 167, 167))
    palette.setColor(QtGui.QPalette.WindowText, QtGui.QColor(51, 19, 19))
    palette.setColor(QtGui.QPalette.Base, QtGui.QColor(255, 230, 230))
    palette.setColor(QtGui.QPalette.Text, QtGui.QColor(100, 0, 0))
    palette.setColor(QtGui.QPalette.Highlight, QtGui.QColor(77, 0, 0).lighter())
    palette.setColor(QtGui.QPalette.HighlightedText, QtCore.Qt.white)
    return palette