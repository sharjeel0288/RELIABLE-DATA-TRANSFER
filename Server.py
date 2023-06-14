import os
import pickle
import socket
from socket import timeout
from threading import Thread
from random import randint
from datetime import datetime
from hashlib import sha1
from tkinter import *
from _thread import *
from threading import *

timeout_sec = 2
loss_probability = 10
chunk_size = 2 * 1024
packet_size = 3 * 1024
packet_count = 1000
client_timeout_trials = 50000

class Server_GUI:

    def __init__(self, root):

        self.root = root
        self.port_number = StringVar()
        self.pack_size = StringVar()
        self.pack_count = StringVar()
        self.loss_prob = StringVar()
        self.root.title('Server - RDT-3.0')
        self.root.geometry("450x380")

        self.create_GUI()

    def create_GUI(self):

        font = 10
        port_label = Label(self.root, text="Port Number : ", font=("Arial", font))
        port_label.place(x=10, y=10)

        entry_box1 = Entry(self.root, textvariable=self.port_number, width=15, bg="white", borderwidth=2, relief="groove")
        entry_box1.place(x=120, y=11)

        self.listen_button = Button(self.root, text="Start Listening", width=14, height=1, command=self.click, borderwidth=1, relief="solid")
        self.listen_button.place(x=230, y=10, height=45)

        # label and entry box for packet size
        p_size_label = Label(self.root, text="Packet Size : ", font=("Arial", font))
        p_size_label.place(x=10, y=65)
        entry_box2 = Entry(self.root, textvariable=self.pack_size, width=15, bg="white", borderwidth=2, relief="groove")
        entry_box2.place(x=120, y=66)

        # label and entry box for packet count
        p_count_label = Label(self.root, text="Packet Count : ", font=("Arial", font))
        p_count_label.place(x=10, y=90)
        entry_box3 = Entry(self.root, textvariable=self.pack_count, width=15, bg="white", borderwidth=2, relief="groove")
        entry_box3.place(x=120, y=91)
        
        # label and entry box for loss probability
        loss_prob_label = Label(self.root, text="Loss Probability : ", font=("Arial", font))
        loss_prob_label.place(x=10, y=115)
        entry_box4 = Entry(self.root, textvariable=self.loss_prob, width=15, bg="white", borderwidth=2, relief="groove")
        entry_box4.place(x=120, y=116)

        # button to save all the data
        save_button = Button(self.root, text="SAVE", width=14, height=1, command=self.save_values, borderwidth=1, relief="solid")
        save_button.place(x=230, y=150, height=25)

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
        Label(self.sframe, text='A client has entered the chat', width=52, justify=CENTER, borderwidth=1, relief="solid", bg="white").pack(padx=0, pady=0)

    # function to start up the server
    def click(self):
        global port_number

        status_label = Label(self.root, text="STATUS: LISTENING", width=25, font=("Arial", 10), borderwidth=2, relief="groove", justify=CENTER)
        status_label.place(x=10, y=40)

        self.listen_button['state'] = 'disabled'

        port_number = int(self.port_number.get())

        self.server = Server(port=port_number, guiobj=self)
        start_new_thread(self.server.listen, ())

    # function to save the input boxes values
    def save_values(self):
        global packet_size, packet_count, loss_probability

        packet_size = int(self.pack_size.get()) * 1024
        packet_count = int(self.pack_count.get())
        loss_probability = int(self.loss_prob.get())

    # make label for the live feed
    def make_label(self, data):
        Label(self.sframe, text=data, width=52, anchor=W).pack(padx=0, pady=0)


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
class Server:
    def __init__(self, ip='127.0.0.1', port=4125, guiobj=None):
        self.ip, self.port = ip, port
        self.address = (self.ip, self.port)
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind(self.address)
        self.thread_count = 0
        self.guiobj = guiobj

    # function to start listening for incoming connections
    def listen(self):
        global timeout_sec

        self.socket.listen()
        print('[Listening on ]', self.address)
        while True:
            try:
                client, address = self.socket.accept()
                
                self.guiobj.make_label(f'Client connected, address: {address}')
                client.settimeout(timeout_sec)  

                # create new thread to serve the client
                thread = Thread(target=self.serve_client, args=(client, address))
                thread.start()
                self.thread_count += 1
                self.guiobj.make_label(f'Client No: {str(self.thread_count)}')

            except KeyboardInterrupt:
                print('\nServer Terminated, waiting for all threads to join')
                break

    # Send packet to the client & wait for positive ack
    # Returns 1 on success else 0
    def send_packet(self, packet, client):

        global loss_probability, packet_size

        seq_num = packet.get_packet_field('seq_num')
        client_timeout_count = client_timeout_trials
        while client_timeout_count:
            if randint(1, 100) > loss_probability:
                client.send(packet.dump_data())

            else:
                self.guiobj.make_label(f'Simulating Packet Loss: {seq_num}')

            # wait for response or timeout
            try: 
                res = client.recv(packet_size)
                if not res:
                    self.guiobj.make_label('Client Disconnected')
                    return 0
                pkt = Packet(pickled=res)
                self.print_packet_details(pkt)
                if pkt.get_packet_field('ack') == '+':
                    return 1
                elif not pkt.validate_packet():
                    self.guiobj.make_label(f'Negative ack, resending: {seq_num}')
                else:
                    self.guiobj.make_label('Packet corrupted and therefore invalid to use')
            except timeout:
                self.guiobj.make_label(f'Timeout, resending packet: {seq_num}')
                client_timeout_count -= 1
        return 0

    # return file request packet or zero after time out
    def wait_for_request(self, client, address):

        global packet_size

        client_timeout_count = client_timeout_trials
        while client_timeout_count:
            try:
                request = client.recv(packet_size)

                if request:
                    pkt = Packet(pickled=request)
                    self.print_packet_details(pkt)
                    return pkt
                else:
                    self.guiobj.make_label(f'Client disconnected, address: {address}')
                    break
            except timeout:
                client_timeout_count -= 1
        return 0

    def serve_client(self, client, address):

        global chunk_size, packet_size

        total_time = datetime.now()
        pkt = self.wait_for_request(client, address)
        if not pkt:
            return 1

        file = 'server/' + pkt.get_packet_field('file')

        # if file is found on the server
        if os.path.isfile(file): 
            pkt = Packet(status='found')
            client.send(pkt.dump_data())

            # sequence numbers for keeping track
            seq_num = 0
            bits = 0
            f = open(file=file, mode='rb')

            chunk_size = packet_size - 1024
            data = f.read(chunk_size)
            
            while data and (seq_num <= packet_count):
                bits += 8 * len(data)

                # make packet with the chunk acquired from the file
                pkt = Packet(data=data, seq_num=seq_num)

                # send packet and check for positive ack
                if not self.send_packet(pkt, client):
                    break

                # increase sequence number if '+' ack and break if '-' ack
                seq_num += 1
                data = f.read(chunk_size)

            # print total time for sending the file
            total_time = (datetime.now() - total_time).total_seconds()
            self.guiobj.make_label(f'Sent {str(bits)} bits, in  {str(total_time)} secs')

        # if file not found, send not found packet
        else:  
            pkt = Packet(status='not_found')
            client.send(pkt.dump_data())

        # close the connection when delivered the file
        self.guiobj.make_label(f'Client disconnected, address: {address}')
        client.close()

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
                

if __name__ == "__main__":

    root = Tk()
    server = Server_GUI(root)
    root.mainloop() 