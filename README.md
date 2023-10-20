# Vulnr
Python script to detect running vulnerable drivers for privilege escalation using the loldrivers api.

```py
import win32com.client
import hashlib
import requests
class vulnr_t:
    def get_vulnerable_drivers(self):
        running_vulnerable_drivers = []
        running_drivers = []
        wmi = win32com.client.GetObject("winmgmts:\\\\.\\root\\cimv2")
        items = wmi.ExecQuery("SELECT * FROM Win32_SystemDriver")
        for item in items:
            running_drivers.append({'name': item.Name, 'description': item.Description, 'path': item.PathName, "md5": hashlib.md5(open(item.PathName, 'rb').read()).hexdigest()})
        vulnerable_drivers = requests.get("https://www.loldrivers.io/api/drivers.json").json()
        for running_driver in running_drivers:
            for vulnerable_driver in vulnerable_drivers:
                for vulnerable_sample in vulnerable_driver["KnownVulnerableSamples"]:
                    try:
                        if running_driver["md5"] == vulnerable_sample["MD5"]:
                            running_vulnerable_drivers.append(vulnerable_sample)
                    except:
                        pass
        return running_vulnerable_drivers
```
