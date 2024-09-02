import requests

class Wan_module():
    def log(self, id):
        # IP-adres ophalen van een externe service
        response = requests.get('https://api.ipify.org?format=json')
        if response.status_code == 200:
            ip_address = response.json()['ip']
        else:
            ip_address = 'Onbekend'

        log_file = f"logs/{id}/log_wan.txt"
        with open(log_file, "a") as file:
            file.write(f"Externe IP-adres van gebruiker: {ip_address}\n")
