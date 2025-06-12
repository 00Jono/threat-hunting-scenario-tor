# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/00Jono/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "labby" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop. These events began at 2025-05-22T16:02:09.7532798Z.

**Query used to locate events:**

```kql
DeviceFileEvents
| where FileName startswith "tor"
| where InitiatingProcessAccountName == "labby" 
| where DeviceName == "threat-hunt-lab"
| where Timestamp >= datetime(2025-05-22T15:10:36.8259379Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName

```
![image](https://github.com/user-attachments/assets/00446ed2-339c-4910-8bea-d55bd8d57696)



---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.0.1.exe". Based on the logs returned, at `May 22, 2025 10:13:16 AM`, an employee on the "threat-hunt-lab" device ran the file `tor-browser-windows-x86_64-portable-14.5.2.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "threat-hunt-lab"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.2.exe"
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine

```
![image](https://github.com/user-attachments/assets/f10a4c4a-59ff-4cb3-9eac-a30dcd13b26b)


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "labby" actually opened the TOR browser. There was evidence that they did open it at `2025-05-22T18:31:27.5555161Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "threat-hunt-lab"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```

![image](https://github.com/user-attachments/assets/ebad5c4f-5bfe-41f2-be6b-ae956c813e65)


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2025-05-22T15:16:22.3756675Z`, an employee on the "threat-hunt-lab" device successfully established a connection to the remote IP address `88.99.7.87` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\labby\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents  
| where DeviceName == "threat-hunt-lab"  
| where InitiatingProcessAccountName != "system"  
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")  
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
```
![image](https://github.com/user-attachments/assets/e3de13a1-09c6-4820-8ab5-60aeac1e4cbf)


---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-05-22T14:10:36.0000000Z`
- **Event:** The user "labby" downloaded a file named `tor-browser-windows-x86_64-portable-14.5.2.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\labby\Downloads\tor-browser-windows-x86_64-portable-14.5.2.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-05-22T14:13:16.0000000Z`
- **Event:** The user "labby" executed the file `tor-browser-windows-x86_64-portable-14.5.2.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.5.2.exe /S`
- **File Path:** `C:\Users\labby\Downloads\tor-browser-windows-x86_64-portable-14.5.2.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-05-22T14:14:06.0000000Z`
- **Event:** User "labby" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\labby\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-05-22T14:14:06.0000000Z`
- **Event:** A network connection to IP `88.99.7.87` on port `9001` by user "labby" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\labby\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2025-05-22T14:15:11.0000000Z` - Connected to `212.227.224.217` on port `443`.
  - `2025-05-22T14:15:08.0000000Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-05-22T16:02:09.7532798Z`
- **Event:** The user "labby" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\labby\Desktop\tor-shopping-list.txt`

---

## Summary

On May 22, 2025, user labby on device threat-hunt-lab initiated a series of actions indicating deliberate installation and use of the Tor Browser, a tool often associated with anonymous browsing.
The process began with the download of the Tor installer into the Downloads folder. The installer was executed using a silent install, extracting all necessary files to the Desktop without typical installation prompts. Core Tor components including tor.exe, firefox.exe, and configuration files were created in expected subfolders. Shortly after, the browser was launched, and subprocesses were generated, consistent with the sandboxed and modular nature of Tor's browsing infrastructure. A successful connection was made to a known Tor entry node, confirming real use of the anonymity network. Finally, a text document named tor-shopping-list.txt was created, potentially representing the user’s plan or intentions for using the Tor network. These findings confirm that Tor Browser was fully installed, launched, and actively used on the system by user labby.


---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `labby`. The device was isolated, and the user's direct manager was notified.

---
