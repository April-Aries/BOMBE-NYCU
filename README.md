# BOMBE-NYCU

## Project Structure

```
.
├── BOMBE-main                                  # BOMBE repo clone from https://github.com/bombe-match/bombe-poc
│   ├── bombe-poc.sln
│   ├── edrv1                                   # EDR: Major logic
│   │   ├── Program.cs
│   │   ├── Properties
│   │   │   └── PublishProfiles
│   │   │       └── FolderProfile.pubxml
│   │   └── edr.csproj
│   ├── malv1                                   # Malware: Major logic (NO LONGER USED IN THIS PROJECT)
│   │   ├── Program.cs
│   │   ├── Properties
│   │   │   └── PublishProfiles
│   │   │       └── FolderProfile.pubxml
│   │   └── malware.csproj
│   └── utilities
│       └── shellcodeConverter.py
├── Malware-ProcessInjection                    # Malware process injection: Generate main malware.exe
│   ├── FinalMalware.sln
│   ├── FinalMalware.vcxproj
│   ├── FinalMalware.vcxproj.filters
│   └── Malware-ProcessInjection.cpp
├── Malware-dll                                 # Malware dll: Generate malware dll file
│   ├── Malware-dll.csproj
│   ├── Malware-dll.sln
│   ├── Newtonsoft.Json.dll
│   ├── Program.cs
│   ├── Properties
│   │   └── AssemblyInfo.cs
│   ├── SQLite.Interop.dll
│   ├── System.Data.SQLite.dll
│   └── packages.config
├─.gitignore
└── README.md
```

## Contribution Guideline

* [Commit format]([https://ithelp.ithome.com.tw/articles/10228738](https://docs.google.com/document/d/1QrDFcIiPjSLDn3EL15IJygNPiHORgU1_OOAqWjiDU5Y/edit?tab=t.0#heading=h.greljkmo14y0)): type: malware/edr content
  > Example: add: mal ETW patch
* Modify README - Design
* 📢 **DO NOT SHARE THE SECRET**: make sure the secret keeps `"00000000000000000000000000000000"`

## Design

### Malware

* Challenge File Access Monitor: Using hard link
* Challenge Process Memory Scan: XOR strings containing "BOMBE"
* Process Injection
  * Malware-dll: build the dll version of malware program (main logic)
  * Using [ConfuserEX](https://github.com/yck1509/ConfuserEx) to confuse .dll file
  * Using [TheWover/donut](https://github.com/TheWover/donut) to generate shellcode in binary
    ```
     .\donut.exe -i /PATH/TO/Malware.dll -c Malware_dll.Program -m Run -o shellcode.bin
    ```
  * Using utilities/shellcodeConverter.py transform the binary shellcode to hex format
    ```
    python3 .\converter.py /PATH/TO/shellcode.bin > shellcode
    ```
  * Malware-ProcessInjection: inject the shellcode to bsass.exe
* IAT Hiding
* Persistence: sleep for 30 seconds
* Confuser: [ConfuserEX](https://github.com/yck1509/ConfuserEx)

### EDR

* Challenge Bypass File Access Monitor: Trace process "cmd.exe" with `copy` and `login data` arguments
