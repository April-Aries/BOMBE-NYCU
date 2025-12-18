# converter.py
# 用法: python converter.py malware.bin
import sys

def main():
    if len(sys.argv) < 2:
        print("Usage: python converter.py <file.bin>")
        return

    file_path = sys.argv[1]
    
    try:
        with open(file_path, "rb") as f:
            content = f.read()
            
        print(f"unsigned char shellcode[{len(content)}] = {{")
        
        # 每行印 16 個 byte
        for i in range(0, len(content), 16):
            chunk = content[i:i+16]
            hex_str = ", ".join([f"0x{b:02x}" for b in chunk])
            print(f"    {hex_str},")
            
        print("};")
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()