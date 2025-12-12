using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace edr
{
    public class SignatureRule
    {
        public string RuleName { get; set; }
        public byte[] Pattern { get; set; }

        public SignatureRule(string name, byte[] pattern)
        {
            RuleName = name;
            Pattern = pattern;
        }
    }
    public static class MemoryScanner
    {
        const int PROCESS_QUERY_INFORMATION = 0x0400;
        const int PROCESS_VM_READ = 0x0010;
        const int MEM_COMMIT = 0x1000;
        const int PAGE_READWRITE = 0x04;
        const int PAGE_EXECUTE_READWRITE = 0x40;

        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll")]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, IntPtr nSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll")]
        public static extern IntPtr VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, IntPtr dwLength);

        [DllImport("kernel32.dll")]
        public static extern bool CloseHandle(IntPtr hObject);

        public static List<SignatureRule> LoadRules()
        {
            var rules = new List<SignatureRule>();

            // Rule 1: Plaintext "BOMBE"
            rules.Add(new SignatureRule("Plain_BOMBE", Encoding.ASCII.GetBytes("BOMBE")));

            // Rule 2: Base*
            rules.Add(new SignatureRule("Base32_BOMBE", Encoding.ASCII.GetBytes("IJHU2QSF")));
            rules.Add(new SignatureRule("Base45_BOMBE", Encoding.ASCII.GetBytes("AH8NY9O1")));
            rules.Add(new SignatureRule("Base58_BOMBE", Encoding.ASCII.GetBytes("8Uuekoe")));
            rules.Add(new SignatureRule("Base62_BOMBE", Encoding.ASCII.GetBytes("50rwf7l")));
            rules.Add(new SignatureRule("Base64_BOMBE", Encoding.ASCII.GetBytes("Qk9NQkU")));
            rules.Add(new SignatureRule("Base85_BOMBE", Encoding.ASCII.GetBytes("6;L<B70")));
            rules.Add(new SignatureRule("Base92_BOMBE", Encoding.ASCII.GetBytes("9>u1%3B")));

            // Rule 3: TODO: XOR (Key 0x??)

            // Rule 4: WideChar
            rules.Add(new SignatureRule("Wide_BOMBE", Encoding.Unicode.GetBytes("BOMBE")));

            return rules;
        }

        // 簡單的 Boyer-Moore 或 IndexOf 搜尋
        private static int FindPattern(byte[] buffer, int bytesRead, byte[] pattern)
        {
            if (bytesRead < pattern.Length) return -1;

            for (int i = 0; i <= bytesRead - pattern.Length; i++)
            {
                bool found = true;
                for (int j = 0; j < pattern.Length; j++)
                {
                    if (buffer[i + j] != pattern[j])
                    {
                        found = false;
                        break;
                    }
                }
                if (found) return i;
            }
            return -1;
        }

        public static string Scan(int pid)
        {
            List<SignatureRule> rules = LoadRules();
            IntPtr hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);

            if (hProcess == IntPtr.Zero) return null;

            try
            {
                IntPtr address = IntPtr.Zero;
                MEMORY_BASIC_INFORMATION mbi;

                // 遍歷記憶體區段
                while (VirtualQueryEx(hProcess, address, out mbi, (IntPtr)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION))) != IntPtr.Zero)
                {
                    // 為了效能，只掃描已提交 (Commit) 且可讀寫 (RW/RWE) 的記憶體
                    // 注意：C# 字串有時會在 ReadOnly 區段，視情況可放寬條件
                    if (mbi.State == MEM_COMMIT &&
                       (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_EXECUTE_READWRITE))
                    {
                        byte[] buffer = new byte[(long)mbi.RegionSize];
                        if (ReadProcessMemory(hProcess, address, buffer, mbi.RegionSize, out IntPtr bytesRead))
                        {
                            // 對每個 Rule 進行比對
                            foreach (var rule in rules)
                            {
                                if (FindPattern(buffer, (int)bytesRead, rule.Pattern) != -1)
                                {
                                    return rule.RuleName; // 抓到了！回傳規則名稱
                                }
                            }
                        }
                    }
                    // 移動到下一個區段
                    long nextAddress = (long)address + (long)mbi.RegionSize;
                    address = new IntPtr(nextAddress);
                }
            }
            catch { }
            finally
            {
                CloseHandle(hProcess);
            }

            return null;
        }
    }
    internal class Program
    {
        const string SECRET = "00000000000000000000000000000000";

        // Dictionary to store process ID to executable filename mapping
        private static Dictionary<int, string> processIdToExeName = new Dictionary<int, string>();
        private static HashSet<int> scannedPids = new HashSet<int>(); // 避免重複掃描同一 PID

        // Flag to ensure the answer is sent only once
        private static bool answerSent = false;

        static async Task Main(string[] args)
        {
            using (var kernelSession = new TraceEventSession(KernelTraceEventParser.KernelSessionName))
            {
                Console.CancelKeyPress += delegate (object sender, ConsoleCancelEventArgs e) { kernelSession.Dispose(); };

                Task.Run(() => ScanLoop());

                kernelSession.EnableKernelProvider(
                    KernelTraceEventParser.Keywords.ImageLoad |
                    KernelTraceEventParser.Keywords.Process |
                    KernelTraceEventParser.Keywords.DiskFileIO |
                    KernelTraceEventParser.Keywords.FileIOInit |
                    KernelTraceEventParser.Keywords.FileIO
                );

                kernelSession.Source.Kernel.ProcessStart += processStartedHandler;
                kernelSession.Source.Kernel.ProcessStop += processStoppedHandler;
                kernelSession.Source.Kernel.FileIORead += fileReadHandler;

                kernelSession.Source.Process();
            }
        }

        private static async void ScanLoop()
        {
            while (!answerSent)
            {
                List<int> pidsSnapshot;
                lock (processIdToExeName)
                {
                    pidsSnapshot = new List<int>(processIdToExeName.Keys);
                }

                foreach (int pid in pidsSnapshot)
                {
                    if (scannedPids.Contains(pid)) continue;

                    // 執行掃描
                    string detection = MemoryScanner.Scan(pid);
                    if (detection != null)
                    {
                        string exeName = "";
                        lock (processIdToExeName) { processIdToExeName.TryGetValue(pid, out exeName); }

                        Console.WriteLine($"[ALERT] Malicious Pattern '{detection}' found in PID: {pid} ({exeName})");

                        if (!string.IsNullOrEmpty(exeName))
                        {
                            await SendAnswerToServer(JsonConvert.SerializeObject(new { answer = exeName, secret = SECRET }));
                            answerSent = true;
                            return;
                        }
                    }

                    scannedPids.Add(pid);
                }

                Thread.Sleep(1000);
            }
        }

        private static async void processStartedHandler(ProcessTraceData data)
        {
            lock (processIdToExeName)
            {
                processIdToExeName[data.ProcessID] = data.ImageFileName;
            }

            // Challenge: Bypass File Access Monitor
            if (!answerSent && data.ParentID != 0 && processIdToExeName.TryGetValue(data.ParentID, out var parentName))
            {
                if (data.ImageFileName.ToLower() == "cmd.exe")
                {
                    var args = data.CommandLine?.ToLower();
                    if (args != null && args.Contains("copy") && args.Contains("login data"))
                    {
                        Console.WriteLine("Copy command: {0}, process: {1} with pid {2}, parent process: {3}", data.CommandLine, data.ProcessName, data.ProcessID, parentName);
                        await SendAnswerToServer(JsonConvert.SerializeObject(
                            new
                            {
                                answer = parentName,
                                secret = SECRET
                            }
                        ));

                        // Set the flag to true to disable further handling
                        answerSent = true;
                    }
                }
            }
        }

        private static void processStoppedHandler(ProcessTraceData data)
        {
            lock (processIdToExeName)
            {
                processIdToExeName.Remove(data.ProcessID);
            }
        }

        private static async void fileReadHandler(FileIOReadWriteTraceData data)
        {
            // Check if the answer has already been sent
            if (answerSent) return;

            // Define the full path to the target file
            string targetFilePath = ("C:\\Users\\bombe\\AppData\\Local\\bhrome\\Login Data").ToLower();

            if (data.FileName.ToLower().Equals(targetFilePath))
            {
                string exeName = null;
                lock (processIdToExeName)
                {
                    processIdToExeName.TryGetValue(data.ProcessID, out exeName);
                }

                if (exeName == null || !exeName.StartsWith("BOMBE")) return;

                Console.WriteLine("File read: {0}, process: {1} with pid {2}, exe: {3}", data.FileName, data.ProcessName, data.ProcessID, exeName);

                // Send the executable filename to the server
                if (!string.IsNullOrEmpty(exeName))
                {
                    await SendAnswerToServer(JsonConvert.SerializeObject(
                        new
                        {
                            answer = exeName,
                            secret = SECRET
                        }
                    ));

                    // Set the flag to true to disable further handling
                    answerSent = true;
                }
            }
        }

        private static async Task SendAnswerToServer(string jsonPayload)
        {
            using (HttpClient client = new HttpClient())
            {
                StringContent content = new StringContent(jsonPayload, Encoding.UTF8, "application/json");

                try
                {
                    HttpResponseMessage response = await client.PostAsync("https://submit.bombe.top/submitEdrAns", content);
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
    }
}
