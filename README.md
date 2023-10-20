# Vulnr

```py
import win32com.client
import hashlib
import requests
import psutil
class vulnr_t:
    def get_vulnerable_drivers(self):
        running_vulnerable_drivers = []
        vulnerable_drivers = requests.get("https://www.loldrivers.io/api/drivers.json").json()
        wmi = win32com.client.GetObject("winmgmts:\\\\.\\root\\cimv2")
        running_drivers = wmi.ExecQuery("SELECT * FROM Win32_SystemDriver")
        for running_driver in running_drivers:
            current_driver_md5 = hashlib.md5(open(running_driver.PathName, 'rb').read()).hexdigest()
            for vulnerable_driver in vulnerable_drivers:
                for vulnerable_sample in vulnerable_driver["KnownVulnerableSamples"]:
                    try:
                        if current_driver_md5 == vulnerable_sample["MD5"]:
                            running_vulnerable_drivers.append(vulnerable_sample)
                    except:
                        pass
        return running_vulnerable_drivers
    def get_vulnerable_programs(self):
        running_vulnerable_programs = []
        vulnerable_programs = requests.get("https://lolbas-project.github.io/api/lolbas.json").json()
        for running_program in psutil.process_iter(['exe']):
            current_program_path = running_program.info['exe']
            for vulnerable_program in vulnerable_programs:
                try:
                    for full_path_json in vulnerable_program["Full_Path"]:
                        if current_program_path.lower() == full_path_json["Path"].lower():
                            running_vulnerable_programs.append(vulnerable_program)
                except:
                    pass
        return running_vulnerable_programs
```
