import json
import networkx as nx
import matplotlib.pyplot as plt
import numpy as np
import tkinter as tk
from tkinter import filedialog
import socket
import xmltodict
import uuid
import subprocess
import platform
from matplotlib.offsetbox import OffsetImage
from matplotlib.offsetbox import AnnotationBbox
import os
from getmac import get_mac_address
from tkinter import simpledialog
G = nx.Graph()
root = None
node_ports = {}
node_macs = {}
data = None
node_vendors = {}
node_os = {}

def convert_xml_to_json(xml_string):
    # Převod XML na slovník
    xml_dict = xmltodict.parse(xml_string)

    # Převod slovníku na JSON
    json_data = json.dumps(xml_dict, indent=3)

    return json_data

def open_and_convert_xml():
    file_path = filedialog.askopenfilename(filetypes=[("XML Files", "*.xml")])
    if file_path:
        with open(file_path, "r", encoding="ISO-8859-1") as file:
            xml_string = file.read()
            json_data = convert_xml_to_json(xml_string)

            # Uložení převedeného JSON do souboru
            json_file_path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON Files", "*.json")])
            if json_file_path:
                with open(json_file_path, "w", encoding="utf-8") as json_file:
                    json_file.write(json_data)

                print(f"Převedený JSON byl uložen do souboru: {json_file_path}")
                
# Funkce pro ukončení aplikace
def exit_application():
    okno.quit()
    okno.destroy()
    
def Network_scan():
    try:
        # Vypne interakci s hlavnim oknem
        okno.grab_set()

        # Dostane IP uzivatele a prida /24 masku
        my_ip = get_my_ip_address()
        if my_ip:
            target_ip = f"{my_ip}/24"
        else:
            print("Nenasli jsme Vasi IP adresu.")
            okno.grab_release()  
            return
        # Zapne scan NMAPu
        nmap_command = f"nmap -T4 -A -O -oX najnovsisken.xml {target_ip}"

        # podproces nmapu
        process = subprocess.Popen(nmap_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1, universal_newlines=True)

        # tiskne real-time provoz
        for line in iter(process.stdout.readline, ''):
            print(line.strip())

    
        process.wait()

       
        print(f"Error behem skenovani: {process.returncode}")

     
        okno.grab_release()

    except Exception as e:
        print(f"chyba behem NMAP skenu: {e}")

def Network_scan_linux():
    try:
      
        okno.grab_set()

        my_ip = get_my_ip_address()
        if my_ip:
            target_ip = f"{my_ip}/24"
        else:
            print("Nejsme schopni najit vasi IP adresu.")
            okno.grab_release()  
            return


        nmap_command = f"sudo nmap -T4 -A -O -oX najnovsisken.xml {target_ip}"

        process = subprocess.Popen(nmap_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1, universal_newlines=True)

        for line in iter(process.stdout.readline, ''):
            print(line.strip())

        
        process.wait()

        print(f"Nmap probehl: {process.returncode}")

        okno.grab_release()

    except Exception as e:
        print(f"Error behem skenovani: {e}")



def get_my_mac_address():
    try:
        mac = get_mac_address()
        return mac
    except Exception as e:
        print("Nefunkcni MAC adresa:", e)
        return None

my_mac_address = get_my_mac_address()
if my_mac_address:
    print("Vase MAC adresa je:", my_mac_address)
else:
    print("Vasi MAC adresu jsme nedostali.")

# Funkce na ziskani IP adresy
import socket

def get_my_ip_address():
    try:
        # Pouzije UDP socket na ziskani local adresy
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.1)  # timeout proti bloku
        s.connect(("10.255.255.255", 1))  # connect na broadcast
        ip_address = s.getsockname()[0]
        s.close()
        return ip_address
    except Exception as e:
        return f"adresa nenalezena: {e}"

print("Vase adresa je:", get_my_ip_address())


def get_default_gateway():
    system_platform = platform.system()

    try:
        if system_platform == "Windows":
            result = subprocess.run(['ipconfig', '/all'], capture_output=True, text=True)
            ipconfig_output = result.stdout

            #Najde default gateway
            gateway_line = None
            for line in ipconfig_output.split('\n'):
                if 'Default Gateway' in line:
                    gateway_line = line
                    break

            # Vybere default gateway
            if gateway_line:
                gateway_address = gateway_line.split(':')[-1].strip()
                return gateway_address

        elif system_platform == "Linux":
            result = subprocess.run(['ip', 'route', 'show', 'default'], capture_output=True, text=True)
            route_output = result.stdout

            # Vybere default gateway adresu
            lines = route_output.strip().split('\n')
            if lines:
                fields = lines[0].split()
                if len(fields) >= 3:
                    gateway_address = fields[2]
                    return gateway_address
        else:
            print(f"Vas operacni system nepodprujeme: {system_platform}")
    except Exception as e:
        print(f"Chyba pri vyberu gateway: {e}")
    return None

# Predani default gateway
my_gateway = get_default_gateway()
if my_gateway:
    print("Vase default gateway je:", my_gateway)
else:
    print("Nebyli jsme schopni ziskat Vasi gateway.")




def load_json_file():
    global data, root  
    my_gateway = get_default_gateway()
    file_path = filedialog.askopenfilename(filetypes=[("JSON soubor", "*.json")])
    if file_path:
        with open(file_path, "r") as f:
            data = json.load(f)
            okno.withdraw()

        # Nacteni dat z JSONu
        print("JSON uspesne nacten.")
        # Ziskani dat hosta
        host_record = data['nmaprun']['host']
        
        for host in host_record:
            addresses = host["address"]
            if not isinstance(addresses, list):
                addresses = [addresses] 
            for address in addresses:
                addrtype = address.get("@addrtype")
                addr = address.get("@addr")
                if addrtype == "ipv4":
                    if addr == my_gateway:
                        root = my_gateway

                    # Pridani node do slovniku
                    ports = []
                    if "ports" in host:
                        ports_info = host["ports"].get("port", [])
                        if not isinstance(ports_info, list):
                            ports_info = [ports_info]  
                        for port_info in ports_info:
                            port_id = port_info.get("@portid", "N/A")
                            ports.append(port_id)
                    node_ports[addr] = ports

                    # Pridani MAC adres a vendoru k node 
                    mac_address = next((mac["@addr"] for mac in addresses if mac.get("@addrtype") == "mac"), None)
                    vendor = next((address.get("@vendor") for address in addresses if address.get("@addrtype") == "mac"), None)

                    if mac_address:
                        node_macs[addr] = mac_address
                    if vendor:
                        node_vendors[addr] = vendor

                    # Pridani OS informaci k node
                    os_info = host.get("os")
                    if os_info is not None:
                        os_matches = os_info.get("osmatch", [])
                        if not isinstance(os_matches, list):
                            os_matches = [os_matches]
                        os_name = ", ".join(match.get("@name", "") for match in os_matches)
                        node_os[addr] = os_name


        # Pridani hran mezi nodes
        for host in host_record:
            addresses = host["address"]
            if not isinstance(addresses, list):
                addresses = [addresses]  
            for address in addresses:
                addrtype = address.get("@addrtype")
                addr = address.get("@addr")
                if addrtype == "ipv4" and addr != my_gateway:
                    G.add_edge(addr, root)
        
        visualize_network()


def visualize_network():
    global pos 
    fig, ax = plt.subplots(figsize=(10, 9.5))
    # Pridani barevneho oznaceni
    def assign_node_color(node):
        if node in node_ports:
            num_ports = len(node_ports[node])
            if num_ports >= 1 and num_ports <= 3:
                return 'lightgreen'
            elif num_ports >= 4 and num_ports <= 6:
                return 'khaki'
            elif num_ports >= 7:
                return 'orange'
            else:
                return 'lightblue'
        else:
            return 'blue'  # Zakladni barva pro node bez open portu

    node_colors = [assign_node_color(node) for node in G.nodes]
    
    # Legenda
    legend_ports = {
        '0 Portu': 'lightblue',
        '1-3 Portu': 'lightgreen',
        '4-6 Portu': 'khaki',
        '>7 Portu': 'orange',
    }
    legend_elements = [plt.Line2D([0], [0], marker='o', color='w', markerfacecolor=color, markersize=10, label=label)
                        for label, color in legend_ports.items()]

    plt.legend(handles=legend_elements, title='Rozsah otevrenych portu', loc='upper left')
    
    


    # Funkce na zobrazeni portu a MAC adres pro vybrany node
    def on_click(event):
        if event.inaxes == ax:
            x, y = event.xdata, event.ydata

            # Kliknuti na node 
            closest_node = None
            min_distance = float('inf')
            for node, (nx, ny) in pos.items():
                distance = (nx - x) ** 2 + (ny - y) ** 2
                if distance < min_distance:
                    closest_node = node
                    min_distance = distance

            x, y = pos[closest_node]
            annotation.xy = (x, y)

            # Prirazeni portu a MAC adres k nodu
            if closest_node in node_ports:
                ports = node_ports[closest_node]
                if ports:
                    text = f"{closest_node}\nPorts: {', '.join(map(str, ports))}"
                else:
                    text = closest_node
            else:
                text = closest_node

            # Zobrazeni MAC adres
            if closest_node == root and root in node_macs:
                mac = node_macs[root]
                text += f"\nMAC Address: {mac}"
            elif closest_node in node_macs:
                mac = node_macs[closest_node]
                text += f"\nMAC Address: {mac}"
            elif closest_node == root:  
                mac = get_my_mac_address()
                if mac:
                    text += f"\nMAC Address: {mac}"
            # Zobrazeni vendoru
            vendor = node_vendors.get(closest_node)
            if vendor:
                text += f"\nVendor: {vendor}"

            # Zobrazeni OS name
            os_name = node_os.get(closest_node)
            if os_name:
                text += f"\nOS: {os_name}"

            
            annotation.set_text(text)
            annotation.set_visible(True)
            fig.canvas.draw_idle()


    # Vytvoreni anotace
    annotation = ax.annotate(
        text="",
        xy=(0, 0),
        xytext=(15, 15),
        textcoords='offset points',
        bbox={'boxstyle': 'round', 'fc': 'w'},
        arrowprops={'arrowstyle': '->'}
    )
    annotation.set_visible(False)


    # Vytvoreni vizualizace
    pos = nx.shell_layout(G)
    
    #  Pridani router obrazku
    if root:
        # Nastaveni cesty k routeru
        router_image_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "router.png")
        router_image = plt.imread(router_image_path)

        # Pozice routeru
        router_image_pos = (pos[root][0], pos[root][1] - 0.10)

        # Pozice routeru networkX
        ax.imshow(router_image, extent=[router_image_pos[0] - 0.05, router_image_pos[0] + 0.05, router_image_pos[1] - 0.1, router_image_pos[1] + 0.1], aspect='auto', zorder=3,alpha=1)
        
        #Pridani dalsich zarizeni
    for node in G.nodes:
        if node != root:
            device_image_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "device.png")
            device_image = plt.imread(device_image_path)
            device_image_pos = (pos[node][0], pos[node][1] - 0.10)
            ax.imshow(device_image, extent=[device_image_pos[0] - 0.05, device_image_pos[0] + 0.05, device_image_pos[1] - 0.1, device_image_pos[1] + 0.1], aspect='auto', zorder=3,alpha=1)

    nx.draw(G, pos, with_labels=True, node_size=6000, font_size=10, font_color="black", node_color=node_colors)
    plt.title("Vizualizace site")
    # Spojeni funkce na klik
    fig.canvas.mpl_connect("button_press_event", on_click)
    plt.show()
    okno.deiconify()


# Vytvori hlavni okno4
okno = tk.Tk()
okno.title("Vizualizace site")
# Velikost okna
okno.geometry("600x200")
# Tlacitko na JSON nahrani
load_button = tk.Button(okno, text="Vyberte JSON soubor", command=load_json_file)
load_button.pack(side=tk.LEFT, padx= 10)
# Tlačítko pro otevření XML souboru a převod na JSON
convert_button = tk.Button(okno, text="Konvert XML souboru", command=open_and_convert_xml)
convert_button.pack(side=tk.LEFT,padx=10)

exit_button = tk.Button(okno, text="Exit", command=exit_application,width=5,height=2)
exit_button.pack(side=tk.RIGHT, anchor=tk.SE,padx=10,pady=10)

nmap_button = tk.Button(okno, text="nmap sken",command=Network_scan)
nmap_button.pack(side=tk.LEFT,padx=10)

nmap_button2 = tk.Button(okno, text="nmap sken linux",command=Network_scan_linux)
nmap_button2.pack(side=tk.LEFT,padx=10)
# Spusteni okna
okno.mainloop()
