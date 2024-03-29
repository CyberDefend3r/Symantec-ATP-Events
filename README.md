# Download Symantec EDR Logs via API
Script used to pull logs from the Symantec ATP/EDR console using the API.

**No Longer Maintained. Still works with Symantec API V2.**
  
https://apidocs.securitycloud.symantec.com/#/doc?id=events_resource  
  
**Setup**  
```bash
$ pip install -r requirements.txt
```
create your own "servers.yaml" file in the script directory. See example_servers.yaml file for formating.

**Usage**  

```text  
required arguments:  
  -q  Query       Required! The query to use. Make sure to encapsulate in quotes.  
optional arguments:  
  -s  Server      Server IP. If none set will loop through all servers in servers.yaml file.
  -d  Days        The amount of days you want. Max is 7, default is 0 (meaning now - 0 day).
  -hr Hours       The amount of hours you want. Default is 0 (meaning now - 0 hour).
  -dt Date Time   Specific date and time (yyyy-mm-dd_hh:mm:ss), default is current utc time.
```  
This example would return results for mimikatz from all servers in config with a time range of now - 3 hours.  
```bash
$ ./symantec_api.py -q "file.name:mimikatz_x86.exe OR file.name:mimikatz.exe" -hr 3
```  

**Output**  
Writes files to script directory.  
Filename example "2020-01-21T231451_10-0-0-100.json" (date, time, server ip)  
  
----  
<img src="https://cdn.cdnlogo.com/logos/t/48/twitter.png" width="20px"> [@Cyb3rDefender](https://twitter.com/Cyb3rDefender)
