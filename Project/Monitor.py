import networkx as nx
import matplotlib.pyplot as plt
import nmap
import threading
import time
from flask import Flask, send_file
import tkinter as tk
from tkinter import ttk
from PIL import Image, ImageTk
import os

os.chdir('G:\Computernetworks\Projectv2') #Changing directory for image path

host_list = [] #Declaring list of nodes
old_hosts = ["empty"]  # Compare aganist new host_list to spot disconnected/timeout hosts

def scan_ports(host, nm, edges): 
    nm.scan(host, '1-1024') #Scans from 1-1024
    if host not in nm.all_hosts(): #If host is unreachable
        return
    for proto in nm[host].all_protocols(): #Checks for both TCP and UDP
        lport = nm[host][proto].keys() #retrieves all oopen ports for each protocol
        for port in lport:
            if nm[host][proto][port]['state'] == 'open': #iterates through the ports
                edges.append((host, f'{proto.upper()}:{port}')) # adds the open ports

def scan_hosts(nm):  
    nm.scan(hosts='192.168.1.0/24', arguments='-sn') #Scans from 192.168.1.0->192.168.1.255, -sn for only active IPs
    hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()] #Saves all the hosts in an array
    global old_hosts  # Declare old_hosts as global within the function
    if old_hosts[0] != "empty":   
        for i in range(len(hosts_list)):
            if old_hosts[i] not in hosts_list: #Compares content of array list, if one is missing from new list then it is timed out or disconnected
                print("This node has been timed out or left the network:", old_hosts[i])
    old_hosts = hosts_list #Puts the new list into the old one for the next comparision                
    return hosts_list

def perform_scan(): #GUI element
    btn.config(text="Scanning...", state=tk.DISABLED)
    root.update_idletasks()

    nm = nmap.PortScanner(nmap_search_path=[r"C:\Program Files (x86)\Nmap\nmap.exe"]) #Nmap is a program for scanning networks
    hosts_list = scan_hosts(nm) #scans the network
    edges = []
    PortThreads = []
    for host in nm.all_hosts(): #threading the port scanning process for efficiency, 1 thread for every host on the system
        thread = threading.Thread(target=scan_ports, args=(host, nm, edges))
        PortThreads.append(thread)
        thread.start()
    for thread in PortThreads:
        thread.join()

    G = nx.Graph() #Creating a graph
    for host, _ in hosts_list: #addings nodes
        G.add_node(host)
    for edge in edges: #adding links
        G.add_edge(edge[0], edge[1])

    plt.figure(figsize=(10, 8))  
    nx.draw(G, with_labels=True, node_color='skyblue', edge_color='gray', node_size=2000, font_size=10, font_weight='bold') #draws the graph
    plt.title('Network')

    current_dir = os.getcwd()
    print(f"Current working directory: {current_dir}")
    image_path = os.path.join(current_dir, 'static', 'Network.png')
    print(f"Saving image to: {image_path}") 

    if not os.path.exists('static'):
        os.makedirs('static')

    plt.savefig(image_path) #saves the graph
    plt.close()
    time.sleep(0.5) #waits for a half a second after printing the pic to not read a corrupt/incomplete image
    print("Image saved successfully")  

    display_image()

    btn.config(text="Scan Network", state=tk.NORMAL)

def display_image(): #displaying the image in gui
    image_path = os.path.join('static', 'Network.png') 
    image = Image.open(image_path)
    photo = ImageTk.PhotoImage(image)
    img_label.config(image=photo)
    img_label.image = photo

app = Flask(__name__)

@app.route('/') #activating the web server
def home():
    return '''
    <h1>Image Display</h1>
    <img src="/static/Network.png" alt="Network.png">
    '''

@app.route('/image')
def image():
    return send_file('static/Network.png', mimetype='image/png')

def start_scan(): #scanning thread
    scan_thread = threading.Thread(target=perform_scan)
    scan_thread.start()

def run_tkinter(G, nm): #GUI app
    global root, btn, img_label
    root = tk.Tk()
    root.title("Network Scanner")

    frm = ttk.Frame(root, padding=50)
    frm.grid()

    btn = ttk.Button(frm, text="Scan Network", command=start_scan)
    btn.grid(column=0, row=0, padx=10, pady=10)

    img_label = ttk.Label(frm)
    img_label.grid(column=0, row=1, padx=10, pady=10)

    root.mainloop()

if __name__ == '__main__':
    nm = nmap.PortScanner(nmap_search_path=[r"C:\Program Files (x86)\Nmap\nmap.exe"])
    G = nx.Graph()
    threading.Thread(target=run_tkinter, args=(G, nm)).start()  # Run the Tkinter app in a separate thread
    app.run(debug=False, use_reloader=False, threaded=True)
    print("site deployed")
