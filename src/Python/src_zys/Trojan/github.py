import git
import os
import shutil

class Github():
    def __init__(self,repo_url):
        self.repo_url = repo_url
        
    def check_remote_repo(self):
        """Deze funcite zal de repo controleren of er een config file beschickbaar is zoja return yes """
        try:
            local_directory = "temp_directory"
            repo = git.Repo.clone_from(self.repo_url, local_directory)
            response = None
            config_file_path = os.path.join(local_directory, "config", "config.txt")
            if os.path.exists(config_file_path):
                with open(config_file_path, "r") as file:
                    response = file.read()
            repo.close()
            shutil.rmtree(local_directory)
            if response:
                return True
            else:
                return False
        except Exception as e:
            print(f"An error occurred: {str(e)}")
            return False

    def get_config(self):
        """Nieuwe config halen van github en de oude verwijderen"""
        try:
            local_directory = "temp_directory"
            repo = git.Repo.clone_from(self.repo_url, local_directory)
            config_dir = os.path.join(local_directory, "config")
            current_config_dir = "config"
            # Delete the existing 'config.txt' file
            current_config_file = os.path.join(current_config_dir, "config.txt")
            os.remove(current_config_file)
            # Copy the 'config.txt' file from 'temp_dir' to the current directory
            temp_config_file = os.path.join(config_dir, "config.txt")
            shutil.copy2(temp_config_file, current_config_dir)
            # Clean up temporary directory
            shutil.rmtree(local_directory)

            return True
        except (git.exc.GitCommandError, FileNotFoundError):
            return False

    def load_modules(self):
        """Modules inladen van github """
        try:
            local_directory = "temp_directory"
            repo = git.Repo.clone_from(self.repo_url, local_directory)
            if os.path.exists('modules'):
                shutil.rmtree('modules')
            logs_directory = os.path.join(local_directory, "modules")
            shutil.copytree(logs_directory,"modules")            
            shutil.rmtree(local_directory)
            return True
        except (git.exc.GitCommandError, FileNotFoundError):
            return False

    def send_logs_to_github(self,id):
        """Deze functie zal de inhoud van de map logs kopieren naar temp_dir en vervolgens de log files gaan versturen naar github """
        try:
            
            local_directory = "temp_directory"
            repo = git.Repo.clone_from(self.repo_url, local_directory)
            logs_directory = os.path.join(local_directory, "logs" , id)
            temp_dir = os.path.join(local_directory, "logs" , id)
            
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)

            shutil.copytree('logs', logs_directory)            
            repo.git.add(all=True)
            repo.index.commit("Add new log entries")
            origin = repo.remote(name="origin")
            origin.push()
            repo.close()

            shutil.rmtree(local_directory)
            return True
        except (git.exc.GitCommandError, FileNotFoundError):
            return False