#!/usr/bin/python3
import socket,sys,threading,time,tkinter
from tkinter import *
from PIL import Image, ImageTk

 
# ==== Scan Vars ====
ip_s = 1
ip_f = 1024
log = []
ports = []
target = []
x=22
ba=[]
 
# ==== Scanning Functions ====
def scanPort(target, port):

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4)
        c = s.connect_ex((target, port))
        
        if c == 0:
            m = ' Port %d \t[open]' % (port,) 
            
            log.append(m)
            ports.append(port)
            listbox.insert("end", str(m))
            ban(target,x)
            updateResult()
            
        s.close()
        
    except OSError: print('> Too many open sockets. Port ' + str(port))
    except:
        c.close()
        s.close()
        sys.exit()
    sys.exit()
     

def ban(target,port):

    try: 
        sb=socket.socket()
        sb.connect((target, 22))
        sb.settimeout(5)
        banner=sb.recv(1024)
        listbox.insert("end",str(banner))
        return(ba)
    except:
         return()
    

def updateResult():
    rtext = " [ " + str(len(ports)) + " / " + str(ip_f) + " ] ~ " + str(target)
    L27.configure(text = rtext)    
 
def startScan():
    print('[+]Scanning')
    global ports, log, target, ip_f
    clearScan()
    log = []
    ports = []
    # Get ports ranges from GUI
    ip_s = int(L24.get())
    ip_f = int(L25.get())
    # Start writing the log file
    log.append('> Port Scanner')
    log.append('='*14 + '\n')
    log.append(' Target:\t' + str(target))
     
    try:
        target = socket.gethostbyname(str(L22.get()))
        log.append(' IP Adr.:\t' + str(target))
        log.append(' Ports: \t[ ' + str(ip_s) + ' / ' + str(ip_f) + ' ]')
        log.append('\n')
        log.append('OS Detection :\t'+str(ba))
        # Lets start scanning ports!
        while ip_s <= ip_f:
            try:
                scan = threading.Thread(target=scanPort, args=(target, ip_s))
              
                scan.setDaemon(True)
                scan.start()
            
            except: time.sleep(0.01)
            ip_s += 1
    except socket.gaierror:
        m = '> Target ' + str(L22.get()) + ' not found.'
        log.append(m)
        listbox.insert(0, str(m))
         
def saveScan():
    global log, target, ports, ip_f
    log[5] = " Result:\t[ " + str(len(ports)) + " / " + str(ip_f) + " ]\n"
    with open('portscan-'+str(target)+'.txt', mode='wt', encoding='utf-8') as myfile:
        myfile.write('\n'.join(log))
 
def clearScan():
    listbox.delete(0, 'end')

 
# ==== GUI ====
gui = Tk()
gui.geometry("1000x1000")
gui.title('Vulnerb')
image1 = Image.open("vulicon(2).jpeg")
test = ImageTk.PhotoImage(image1)

label1 = tkinter.Label(image=test)
label1.image = test

# Position image
label1.place(x=500, y=60)

 
# ==== Colors ====
m1c = 'black'
bgc = 'white'
dbg = '#fff'
fgc = 'cornsilk3'
 
gui.tk_setPalette(background=bgc, foreground=m1c, activeBackground=fgc,activeForeground=bgc, highlightColor=m1c, highlightBackground=m1c)
 
# ==== Labels ====
L11 = Label(gui, text = "Vulnerb",  font=("Helvetica", 16, 'underline'))
L11.place(x = 500, y = 10)
 
L21 = Label(gui, text = "Target: ")
L21.place(x = 16, y = 90)
 
L22 = Entry(gui, text = "localhost")
L22.place(x = 180, y = 90)
L22.insert(0, "localhost")
 
L23 = Label(gui, text = "Ports: ")
L23.place(x = 16, y = 158)
 
L24 = Entry(gui, text = "1")
L24.place(x = 180, y = 158, width = 95)
L24.insert(0, "1")
 
L25 = Entry(gui, text = "1024")
L25.place(x = 290, y = 158, width = 95)
L25.insert(0, "1024")
 
L26 = Label(gui, text = "Results: ")
L26.place(x = 16, y = 220)
L27 = Label(gui, text = "[ ... ]")
L27.place(x = 180, y = 220)
 
# ==== Ports list ====
frame = Frame(gui)
frame.place(x = 16, y = 275, width = 870, height = 215)
listbox = Listbox(frame, width = 89, height = 13)
listbox.place(x = 0, y = 0)
listbox.bind('<<ListboxSelect>>')
scrollbar = Scrollbar(frame)
scrollbar.pack(side=RIGHT, fill=Y)
listbox.config(yscrollcommand=scrollbar.set)
scrollbar.config(command=listbox.yview)
 
# ==== Buttons / Scans ====
B11 = Button(gui, text = "Start Scan", command=startScan)
B11.place(x = 16, y = 600, width = 270)
B21 = Button(gui, text = "Save Result", command=saveScan)
B21.place(x = 400, y = 600, width = 270)

 
# ==== Start GUI ====
gui.mainloop()
