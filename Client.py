import os
from socket import timeout
from random import randint
from hashlib import sha1
import pickle 
import socket
from tkinter import *
from _thread import *
from threading import *

filename = ''
timeout_sec = 2
corruption_probability = 10
packet_size = 3 * 1024
client_timeout_trials = 5

class Client_GUI:

    def __init__(self, root):

        self.root = root
        self.port_number = StringVar()
        self.filename = StringVar()
        self.pack_size = StringVar()
        self.corr_prob = StringVar()
        self.root.title('Client - RDT-3.0')
        self.root.geometry("450x380")

        self.create_GUI()

    def create_GUI(self):

        font = 10
        port_label = Label(self.root, text="Enter IP and Port : ", font=("Arial", font))
        port_label.place(x=10, y=10)

        entry_box1 = Entry(self.root, textvariable=self.port_number, width=40, bg="white", borderwidth=2, relief="groove")
        entry_box1.place(x=10, y=35)

        self.connect_button = Button(self.root, text="CONNECT", width=15, height=1, command=self.click, borderwidth=1, relief="solid")
        self.connect_button.place(x=270, y=35, height=45)

        # label and entry box for file name
        file_label = Label(self.root, text="Filename : ", font=("Arial", font))
        file_label.place(x=10, y=90)
        entry_box2 = Entry(self.root, textvariable=self.filename, width=26, bg="white", borderwidth=2, relief="groove")
        entry_box2.place(x=90, y=90)

        # label and entry box for packet size
        p_size_label = Label(self.root, text="Packet Size : ", font=("Arial", font))
        p_size_label.place(x=10, y=115)
        entry_box3 = Entry(self.root, textvariable=self.pack_size, width=16, bg="white", borderwidth=2, relief="groove")
        entry_box3.place(x=150, y=115)
        
        # label and entry box for corruption probability
        corr_prob_label = Label(self.root, text="Corruption Probability : ", font=("Arial", font))
        corr_prob_label.place(x=10, y=140)
        entry_box4 = Entry(self.root, textvariable=self.corr_prob, width=16, bg="white", borderwidth=2, relief="groove")
        entry_box4.place(x=150, y=140)

        # button to start the transfer
        start_button = Button(self.root, text="START TRANSFER", width=15, height=1, command=self.start_transfer, borderwidth=1, relief="solid")
        start_button.place(x=270, y=115, height=49)

        live_feed_label = Label(self.root, text="Live Feed", font=("Arial", font))
        live_feed_label.place(x=10, y=180)

        self.reply_frame = Frame(self.root, borderwidth=1, relief="solid")
        self.reply_frame.place(x=10, y=205)

        self.reply_canvas = Canvas(self.reply_frame, width=400, height=150)
        self.reply_canvas.pack(side=LEFT, fill=BOTH, expand=YES)

        reply_scrollbar = Scrollbar(self.reply_frame, orient=VERTICAL, command=self.reply_canvas.yview)
        reply_scrollbar.pack(side=RIGHT, fill=Y, pady=10)

        self.sframe = Frame(self.reply_canvas, width=400, height=140)
        self.sframe.pack()
        self.sframe.bind("<Configure>", lambda e: self.reply_canvas.configure(scrollregion=self.reply_canvas.bbox("all")))

        self.reply_canvas.configure(yscrollcommand=reply_scrollbar.set)
        self.reply_canvas.bind('<Configure>', lambda e: self.reply_canvas.configure(scrollregion=self.reply_canvas.bbox("all")))

        self.reply_canvas.create_window((0,0), window=self.sframe, anchor="nw")


    def show_connected(self):
        status_label = Label(self.root, text="CONNECTED", width=30, font=("Arial", 10), borderwidth=2, relief="groove", justify=CENTER)
        status_label.place(x=10, y=60)


    def click(self):  
        address = self.port_number.get().split(':')
        port_number = int(address[1])
        serverIP = address[0]

        self.client = Client(ip=serverIP, port=port_number, guiobj=self)
        start_new_thread(self.client.connect, ())
        

    def make_label(self, data):
        Label(self.sframe, text=data, width=52, anchor=W).pack(padx=0, pady=0)


    def start_transfer(self):
        global packet_size, packet_count, corruption_probability, filename

        packet_size = int(self.pack_size.get()) * 1024
        corruption_probability = int(self.corr_prob.get())
        filename = self.filename.get()

        self.client.request(filename)

# packet class for creating packet objects
class Packet:
    def __init__(self, pickled=None, seq_num=0, data=b'', ack='', file='', status=''):
        # if data is pickled then unpickle it
        if pickled is not None:
            self.packet = pickle.loads(pickled)

        else:
            self.packet = {
                "status": status,
                "file": file,
                "ack": ack,
                "seq_num": seq_num,
                "checksum": sha1(data).hexdigest() if data else '',
                "data": data
            }

    def dump_data(self): 
        dumped = pickle.dumps(self.packet)
        return dumped

    def validate_packet(self):
        return self.packet['checksum'] == sha1(self.packet['data']).hexdigest()

    def get_packet_field(self, field):
        if field == 'seq_num':
            return str(self.packet[field])
        else:
            return self.packet[field]


# server class for implementing the server 
class Client:
    def __init__(self, ip='localhost', port=4125, guiobj=None):
        self.guiobj = guiobj
        self.ip, self.port = ip, port
        self.server_address = (self.ip, self.port)
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # function to connect to the server
    def connect(self):
        
        global timeout_sec

        self.socket.connect(self.server_address)
        self.socket.settimeout(timeout_sec)
        self.guiobj.make_label(f'Connected to {self.server_address}')

        self.guiobj.show_connected()

    # function to request the file from the server
    def request(self, file):

        global packet_size, client_timeout_trials

        # send file request and wait for response
        timeout_trials = client_timeout_trials

        while timeout_trials:
            # send file request in packet
            pkt = Packet(file=file)
            self.socket.send(pkt.dump_data())

            try:
                res = self.socket.recv(packet_size)
                if not res:
                    self.guiobj.make_label(f'Disconnected from {self.server_address}')
                    break

                pkt = Packet(pickled=res)
                start_new_thread(self.print_packet_details, (pkt,))

                if pkt.get_packet_field('status') == 'found':
                    self.guiobj.make_label('File Found on Server')
                    break
                elif pkt.get_packet_field('status') == 'not_found':
                    self.guiobj.make_label('File Not Found')
                    break
                else:
                    self.guiobj.make_label('Bad response')
                    break
            except timeout:
                self.guiobj.make_label('File request timeout')
                timeout_trials -= 1

        if timeout_trials:
            self.recv_file(file)


    # function to recieve the file
    def recv_file(self, file):

        global corruption_probability

        self.socket.settimeout(None)

        # replicate the filename in the client folder
        received_file = 'client/' + file
        self.make_file(received_file)

        f = open(file=received_file, mode='ab')

        while True:
            try:
                res = self.socket.recv(packet_size)
                if not res:
                    self.guiobj.make_label(f'Disconnected from {self.server_address}')
                    break

                pkt = Packet(pickled=res)
                start_new_thread(self.print_packet_details, (pkt,))

                if randint(1, 100) > corruption_probability or not pkt.validate_packet():

                    f.write(pkt.get_packet_field('data'))
                    ack = Packet(seq_num=pkt.get_packet_field('seq_num'), ack='+')
                    self.socket.send(ack.dump_data())

                else:  
                    self.guiobj.make_label(f"Simulating packet corruption (Negative Ack): {pkt.get_packet_field('seq_num')}")
                    ack = Packet(seq_num=pkt.get_packet_field('seq_num'), ack='-')
                    self.socket.send(ack.dump_data())

            except Exception as e:
                print(e)
                break

        f.close()
        self.socket.close()

    def print_packet_details(self, pkt):
        status = pkt.get_packet_field('status')
        file = pkt.get_packet_field('file')
        ack = pkt.get_packet_field('ack')
        seq_num = str(pkt.get_packet_field('seq_num'))

        if ack == '+':
            self.guiobj.make_label(f'Positive Ack {seq_num}')
        elif ack == '-':
            self.guiobj.make_label(f'Negative Ack {seq_num}')
        elif file:
            self.guiobj.make_label('Requesting file: ' + file)
        elif status == 'found':
            self.guiobj.make_label('File is found, recieving')
        elif status == 'not_found':
            self.guiobj.make_label('File not found')
        else:
            self.guiobj.make_label(f'Recieved Packet {seq_num}')


    def make_file(self, file):
        # make the client folder if not present
        if not os.path.isdir('client'):
            os.mkdir('client')
        
        open(file=file, mode='wb').close()


if __name__ == "__main__":

    root = Tk()
    client = Client_GUI(root)
    root.mainloop()



