# BOMBE-NYCU

## Project Structure

```
├─edrv1
|   ├─Properties
|   |   └─PublishProfiles
|   ├─Program.cs            # EDR code
|   └─edr.csproj
├─malv1
|   ├─Properties
|   |   └─PublishProfiles
|   ├─Program.cs            # Malware code
|   └─malware.csproj
├─utilities
|   └─shellodeConverter.py  # Convert dll shellcode made from donut to hex format
├─.gitignore
├─README.md
└─bombe-poc.sln
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
  * Using [TheWover/donut](https://github.com/TheWover/donut) to generate shellcode in binary
    ```
     .\donut.exe -i /PATH/TO/Malware.dll -c Malware_dll.Program -m Run -o shellcode.bin
    ```
  * Using utilities/shellcodeConverter.py transform the binary shellcode to hex format
    ```
    python3 .\converter.py /PATH/TO/shellcode.bin > shellcode
    ```
  * Malware-ProcessInjection: inject the shellcode to bsass.exe

### EDR

* Challenge Bypass File Access Monitor: Trace process "cmd.exe" with `copy` and `login data` arguments
