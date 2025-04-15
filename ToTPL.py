import requests
import time
import logging

class Interface_menu:
    def __init__(self):
        self.color_green = "\033[32m"
        self.color_yellow = "\033[33m"
        self.color_red = "\033[31m"
        self.color_reset = "\033[00m"

    def logotip(self):
        """Logo of the program that is displayed upon startup"""
        print(rf"""{self.color_green}
 _____   _____ ____  _     
|_   _|_|_   _|  _ \| |    
  | |/ _ \| | | |_) | |    
  | | (_) | | |  __/| |___ 
  |_|\___/|_| |_|   |_____|

  by: Ratbb
        {self.color_reset}""")

    def interface(self):
        """Interface program"""
        print("""
[+]1.Scan url🔍
[+]2.Scan files for viruses🦠
[+]3.Checking Api-key limits🔑
[+]4.Change Api-key🔁
[+]5.Exit from ToTPL🚪
""")    

class VirusScanner:
     def __init__(self, interface):
        self.interface = interface
        logging.basicConfig(format=("%(asctime)s - %(message)s"), datefmt="[+]%Y-%d-%m %H:%M:%S")
        logging.basicConfig(level=logging.INFO)

        try:
            while True:
                print(f"{self.interface.color_yellow}[+]P.S: To exit the program press Ctrl+C{self.interface.color_reset}")
                print(f"{self.interface.color_yellow}[+]Path not entered. P.S: To update your Api-key, enter: '0'{self.interface.color_reset}")
                self.name_file_for_api = input("[+]Enter the path where your file with api-key stored: ").strip("''").strip("''").lstrip("' ").lstrip("& ").rstrip(" '")
               
                if self.name_file_for_api == "0":
                    print(f"{self.interface.color_yellow}[+]Skipping Api-key setup...{self.interface.color_reset}")
                    self.name_file_for_api = None
                    break

                if self.name_file_for_api:
                    break
        
        except KeyboardInterrupt:
            logging.warning(f"{self.interface.color_yellow}[+]You have left the program...{self.interface.color_reset}")
          
     def api_key_user_update(self):
        """Api-key update"""
        try:
            user_api = input(f"{self.interface.color_yellow}[+]Enter your api key: {self.interface.color_reset}")
            self.name_file_for_api = input(f"{self.interface.color_yellow}[+]Enter the path where you want to save the file: {self.interface.color_reset}")
        
            with open(self.name_file_for_api, "w") as write_api_user: 
                time.sleep(2)
                logging.info("[+]Updating and saving the file...")
                write_api_user.write(user_api)

            with open(self.name_file_for_api, "r") as read_api_update:
                self.user_api_key = read_api_update.read() 
                logging.info(f"[+]Your updated Api-key: {self.user_api_key} ") 
        except FileNotFoundError:
            logging.error(f"{self.interface.color_red}[+]File not found: {self.interface.color_reset}{self.name_file_for_api}")
        
     def api_key_user(self):
        """Reads user file the api"""
        try:
            with open(self.name_file_for_api, "r") as read_api:
                self.user_api_key = read_api.read()          
        except FileNotFoundError:
            logging.error(f"{self.interface.color_red}[+]File not found: {self.interface.color_reset}{self.name_file_for_api}")
        except TypeError:
            logging.error(f"{self.interface.color_red}[+]Error! make sure you entered the correct Api-key or path to it{self.interface.color_reset}")
        except OSError as e:
            logging.error(f"{self.interface.color_red}[+]Error! Check your Api file, make sure it is definitely a api file: {e}{self.interface.color_reset}")
        except UnicodeDecodeError:
            logging.error(f"{self.interface.color_red}[+]Error! make sure your are sending a text file{self.interface.color_reset}")

     def scan_url(self):
        """URLs are scanned for suspicious and malicious URLs"""
        try:
            url_users = input(f"{self.interface.color_yellow}[+]Enter url: {self.interface.color_reset}")
            url_main = "https://www.virustotal.com/api/v3/urls"
            response_post = requests.post(url_main, headers={"x-apikey":self.user_api_key}, data={"url":url_users})
            id_users = response_post.json().get('data').get('id')
            response_get = requests.get(f"https://www.virustotal.com/api/v3/analyses/{id_users}", headers={"x-apikey":self.user_api_key})
            status_url = response_get.json().get('data',{}).get('attributes',{}).get('status')
            print("[+]Loading......")

            while status_url != "completed":
                time.sleep(20)
                response_get = requests.get(f"https://www.virustotal.com/api/v3/analyses/{id_users}", headers={"x-apikey":self.user_api_key})
                status_url = response_get.json().get('data',{}).get('attributes',{}).get('status')
            status = response_get.json()
            stats = status.get('data').get('attributes').get('stats')
            malicious = stats.get('malicious')
            suspicious = stats.get('suspicious')
         
            if malicious == 0 and suspicious == 0:
                print(f"malicious not found✅: {self.interface.color_green}{malicious}{self.interface.color_reset}")
                print(f"suspicious not found✅: {self.interface.color_green}{suspicious}{self.interface.color_reset}")
            elif malicious > 0:
                print(f"Malicious found⚠️: {malicious}")
            elif suspicious > 0:
                print(f"Suspicious found⚠️ {suspicious}")
        
        except AttributeError:
            logging.error(f"{self.interface.color_red}[+]Error! check the api key and the path to it, and also make sure that you entered the correct data{self.interface.color_reset}")
        except requests.exceptions.ConnectionError: 
            logging.error(f"{self.interface.color_red}[+]Error! make sure you have a connection {self.interface.color_reset}")   
     
     def scan_file(self):
        """Checks files for malware"""
        try:
            user_file = input(f"{self.interface.color_yellow}[+]Enter the path to your file: {self.interface.color_reset}").strip("''").lstrip("' ").rstrip(" '")
            url_files_virsus = "https://www.virustotal.com/api/v3/files"
            with open (user_file, "rb") as file:
                response = requests.post(url_files_virsus, headers={"x-apikey":self.user_api_key}, files={"file": file})
            
            id_file = response.json().get('data').get('id')
            url_files_id = f"https://www.virustotal.com/api/v3/analyses/{id_file}"
            response_get = requests.get(url_files_id, headers={"x-apikey":self.user_api_key})
            status_file = response_get.json().get('data',{}).get('attributes',{}).get('status')
            logging.basicConfig(level=logging.INFO)
            print("[+]Loading......")
            
            while status_file != "completed":
                time.sleep(10)
                response_get = requests.get(url_files_id, headers={"x-apikey":self.user_api_key})
                status_file = response_get.json().get('data',{}).get('attributes',{}).get('status')
            analyses_virsus = response_get.json().get('data').get('attributes').get('stats')
            file_mailcious = analyses_virsus.get('malicious')
            file_suspicious = analyses_virsus.get('suspicious')
            
            if file_mailcious == 0 and file_suspicious == 0:
                print(f"[+]Malicious not found✅: {self.interface.color_green}{file_mailcious}{self.interface.color_reset}")
                print(f"[+]Suspicious not found✅: {self.interface.color_green}{file_suspicious}{self.interface.color_reset}")
            elif file_mailcious > 0:
                print(f"[+]Malicious found⚠️: {self.interface.color_red}{file_mailcious}{self.interface.color_reset}")
            elif file_suspicious > 0:
                print(f"[+]Suspicious found⚠️: {self.interface.color_red}{file_suspicious}{self.interface.color_reset}")
        
        except FileNotFoundError as e:
            logging.error(f"{self.interface.color_red}[+]File not found: {self.interface.color_reset}{self.name_file_for_api}{self.interface.color_reset}")
        except requests.exceptions.ConnectionError:
            logging.error(f"{self.interface.color_red}[+]Error! make sure you have a connection {self.interface.color_reset}")
        except OSError as e:
            logging.error(f"{self.interface.color_red}[+]Error! Check your Api file, make sure it is definitely a api file: {e}{self.interface.color_reset}") 
        except AttributeError:
            logging.error(f"{self.interface.color_red}[+]Error! check the api key and the path to it, and also make sure that you entered the correct data{self.interface.color_reset}")    

     def cheack_api_limits(self):
        """Checks ip limit"""
        try:
           url_api_limits = f"https://www.virustotal.com/api/v3/users/{self.user_api_key}/overall_quotas"
           response_api = requests.get(url_api_limits, headers={"x-apikey":self.user_api_key})

           json_api_hourly = response_api.json().get('data').get('api_requests_hourly').get('user')
           used_api_hourly =  json_api_hourly.get('used')
           allowed_api_hourly = json_api_hourly.get('allowed')

           json_api_daily = response_api.json().get('data').get('api_requests_daily').get('user')
           used_api_daily = json_api_daily.get('used')
           allowed_api_daily = json_api_daily.get('allowed')

           json_api_monthly = response_api.json().get('data').get('api_requests_monthly').get('user')
           used_api_monthly = json_api_monthly.get('used')
           allowed_api_monthly = json_api_monthly.get('allowed')

           print(f"""
 _______________
[Api hourly limit]:   
[Used:{used_api_hourly}]
[Allowed:{allowed_api_hourly}]
--_--_--_--_--_--
[Api daily limit]:
[Used:{used_api_daily}]
[Allowed:{allowed_api_daily}]
--_--_--_--_--_--
[Api monthly limit]:
[Used:{used_api_monthly}]
[Allowed:{allowed_api_monthly}]
 _______________
""")
        except AttributeError: 
            logging.error(f"{self.interface.color_red}[+]Error your api-key path maybe incorrect or your Api-key maybe incorrect{self.interface.color_reset}")
        except TypeError:
            logging.error(f"{self.interface.color_red}[+]Error make sure you entered the correct Api-key or path to it{self.interface.color_reset}")
        except UnboundLocalError:
            logging.warning(f"{self.interface.color_red}[+]Check your path and also your Apy-key{self.interface.color_reset}")
        except requests.exceptions.ConnectionError:
            logging.error(f"{self.interface.color_red}[+]Error! make sure you have a connection {self.interface.color_reset}")

     def command_menu(self):
        """Custom string"""
        try:
            while True:
                choice_user = input(f"{self.interface.color_yellow}[+]Enter a number: {self.interface.color_reset}")
                if choice_user == "1":
                    self.api_key_user()
                    self.scan_url()
                elif choice_user == "2":
                    self.api_key_user()
                    self.scan_file()
                elif choice_user == "3":
                    self.api_key_user()
                    self.cheack_api_limits()
                elif choice_user == "4":
                    self.api_key_user_update()
                elif choice_user == "5":
                    logging.info(f"{self.interface.color_yellow}[+]You have left the program...")
                    break
                else:
                    logging.warning(f"{self.interface.color_red}[+]Error! you entered incorrect characters{self.interface.color_reset}")
        
        except KeyboardInterrupt:
            logging.warning(f"{self.interface.color_yellow}[+]You have left the program...{self.interface.color_reset}")


if __name__ == "__main__":
    interface = Interface_menu()
    interface.logotip()
    interface.interface()

    virus = VirusScanner(interface)
    virus.command_menu()

