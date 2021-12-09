import tkinter as tk
from tkinter import *
import tksheet

window =tk.Tk()
window.title("SERVER")
window.geometry("1500x250")

def init_IP():
    ip = ip_address.get(1.0,END)

ip_address=Text(window,width=80,height=1)
ip_address.place(x=80,y=10)
button_frame=Frame(window)
button_frame.pack()

get_ip_button=tk.Button(button_frame,text="SET CLIENT IP",command=init_IP)
get_ip_button.grid(row = 0 ,column=1)
def init_SPORT():
    sport = sport_val.get(1.0, END)


sport_val = Text(window,width=80, height=1)
button_frame2=Frame(window)
button_frame2.place(x=700,y=50)

sport_val.place(x=80,y=50)
get_SPORT_button = tk.Button(button_frame2, text="SET SPORT", command=init_SPORT)
get_SPORT_button.grid(row=5, column=1)

def init_DPORT():
    dport = dport_val.get(1.0, END)


dport_val = Text(window,width=80, height=1)
button_frame3=Frame(window)
button_frame3.place(x=700,y=100)

dport_val.place(x=80,y=100)
get_DPORT_button = tk.Button(button_frame3, text="SET DPORT", command=init_DPORT)
get_DPORT_button.grid(row=5, column=1)


def init_DPORT():
    dport = dport_val.get(1.0, END)


dport_val = Text(window,width=80, height=1)
button_frame3=Frame(window)
button_frame3.place(x=700,y=100)

dport_val.place(x=80,y=100)
get_DPORT_button = tk.Button(button_frame3, text="SET DPORT", command=init_DPORT)
get_DPORT_button.grid(row=5, column=1)


def connect():
    #ne conectam!
    print("Connect")

button_frame4 = Frame(window)
button_frame4.place(x=1400, y=200)
connect = tk.Button(button_frame4, text="CONNECT", command=connect)
connect.grid(row=5,column=1)

window.mainloop()
