import platform
import subprocess
import socket
import time

class Sysinfo_module():
    def log(self, id):
        """systeeminformatie krijgen van de computer """
        log_file = f"logs/{id}/log_sysinfo.txt"
        with open(log_file, "a") as file:
            # Hostnaam
            hostname = socket.gethostname()
            file.write(f"Hostnaam: {hostname}\n")
            
            # Besturingssysteem
            operating_system = platform.system()
            file.write(f"Besturingssysteem: {operating_system}\n")
            
            # Kernelversie
            kernel_version = platform.release()
            file.write(f"Kernelversie: {kernel_version}\n")
            
            # Gebruikersnaam
            username = subprocess.run(['whoami'], capture_output=True, text=True).stdout.strip()
            file.write(f"Gebruikersnaam: {username}\n")

            # Gebruiksduur
            uptime = subprocess.run(['uptime', '-p'], capture_output=True, text=True).stdout.strip()
            file.write(f"Gebruiksduur: {uptime}\n")
            
            # Opslaginformatie
            disk_usage = subprocess.run(['df', '-h'], capture_output=True, text=True).stdout.strip()
            file.write("Opslag:\n")
            file.write(disk_usage)
            
            file.write("\n")  # Voeg een lege regel toe voor scheiding