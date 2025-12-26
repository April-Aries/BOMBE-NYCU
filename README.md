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

### EDR

* Challenge Bypass File Access Monitor: Trace process "cmd.exe" by parent-child relationship
* Distinguish Decoys: Using parent-child relationship backtracking and behavior analysis
* Monitor Registry Read: Using ETW to monitor RegistryOpen
* Monitor File Read: Using ETW to monitor FileIORead with fileID recognition
* Monitor Process Memory Read: Scan each process's memory space with simple static rules once new process is created
* To compile EDR in Visual Studio: 
	> Right-Click EDR Project -> Publish -> Select Target Folder -> Publish