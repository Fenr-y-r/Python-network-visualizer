import networkx as nx #mapping
import matplotlib.pyplot as plt #graphing
import nmap 
import threading
import time  
def scan_ports(host): #Massive performance boost from multithreading
    nm.scan(host, '1-1024')  # Scanning the first 1024 ports
    for proto in nm[host].all_protocols():
        lport = nm[host][proto].keys()
        for port in lport:
            if nm[host][proto][port]['state'] == 'open':
                # Add an edge for the open port
                edges.append((host, f'{proto.upper()}:{port}'))
def scan_hosts(nm): # scans all devices on the network 
    nm.scan(hosts='192.168.1.0/24', arguments='-sn') # scans up to 192.168.1.255 
    hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()] # creates an array of hosts with their status
    return hosts_list
nmap_path=[r"C:\Program Files (x86)\Nmap\nmap.exe",]
nm=nmap.PortScanner(nmap_search_path=nmap_path) #nmap is a program for mapping complex networks 
hosts_list=scan_hosts(nm) 
for host, status in hosts_list: #printing out Hosts in the terminal
    print(f'Host : {host} ({status})')
edges = []
# Scan ports of every host, very slow task so multi threaded
PortThreads = []
for host in nm.all_hosts():
    thread = threading.Thread(target=scan_ports, args=(host,))
    PortThreads.append(thread)
    thread.start()
for thread in PortThreads:
    thread.join()
for edge in edges:
    G = nx.Graph()

# Add nodes to the graph
for host, _ in hosts_list:
    G.add_node(host)

# Add edges to the graph
for edge in edges:
    G.add_edge(edge[0], edge[1])

# Draw the graph using Matplotlib
plt.figure(figsize=(10,8)) #10x8 image
nx.draw(G, with_labels=True, node_color='skyblue', edge_color='gray', node_size=2000, font_size=10, font_weight='bold')
plt.title('Network')
plt.savefig('Network.png') # saves the image
time.sleep(0.5) # waits half a second to read for the GUI to not read an incomplete/corrupt image
print("Imagine printed") #confirmation