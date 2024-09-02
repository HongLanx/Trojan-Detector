import os

class FolderMapper_module():
    def log(self,id):
        """Functie die map /home gaat loggen helemaal  """
        log_file = f"logs/{id}/log_folders.txt"

        home_directory = "/home"
        with open(log_file, "a") as file:
            file.write("Mappen en bestanden in /home:\n\n")
            self._map_files_recursive(home_directory, file, 0)

    def _map_files_recursive(self, directory, file, indent_level):
        indent = "    " * indent_level
        file.write(f"{indent}[{os.path.basename(directory)}]\n")

        try:
            subdirectories = os.listdir(directory)
            for item in subdirectories:
                item_path = os.path.join(directory, item)
                if os.path.isdir(item_path):
                    self._map_files_recursive(item_path, file, indent_level + 1)
                else:
                    file.write(f"{indent}  {item}\n")
        except PermissionError:
            pass

        file.write("\n")  # Add an empty line for separation