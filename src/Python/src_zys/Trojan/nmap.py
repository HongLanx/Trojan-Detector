import nmap

class Nmap_module:
    def log(self,id):
        """Nmap draaien van het lokaal netwerk """
        nm = nmap.PortScanner()

        # Voer de Nmap-scan uit
        nm.scan(hosts='192.168.0.0/24', arguments='-sn')
        log_file = f"logs/{id}/log_nmap.txt"

        with open(log_file, "a") as file:
            # Loop through each scanned device
            for host in nm.all_hosts():
                if 'mac' in nm[host]['addresses']:
                    mac_address = nm[host]['addresses']['mac']
                else:
                    mac_address = 'Unknown'

                ip_address = nm[host]['addresses']['ipv4']
                file.write(f"IP Address: {ip_address}\n")
                file.write(f"MAC Address: {mac_address}\n")
                file.write("\n")  # Add an empty line for separation