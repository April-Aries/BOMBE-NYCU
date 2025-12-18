using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Text;
using System.Threading.Tasks;
using System.Threading;

namespace EDRPOC
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
        //const string SECRET = "00000000000000000000000000000000"; 
        const string SECRET = "uuKVJRNSR89m3Uvpmf8PrI8OnFKyTjHh";



        // --- File ID Helper (No changes needed here, kept for completeness) ---
        public static class FileIdHelper
        {
            [StructLayout(LayoutKind.Sequential)]
            public struct FILE_ID_128
            {
                public byte Identifier0; public byte Identifier1; public byte Identifier2; public byte Identifier3;
                public byte Identifier4; public byte Identifier5; public byte Identifier6; public byte Identifier7;
                public byte Identifier8; public byte Identifier9; public byte Identifier10; public byte Identifier11;
                public byte Identifier12; public byte Identifier13; public byte Identifier14; public byte Identifier15;
                public override string ToString() => BitConverter.ToString(new byte[] { Identifier0, Identifier1, Identifier2, Identifier3, Identifier4, Identifier5, Identifier6, Identifier7, Identifier8, Identifier9, Identifier10, Identifier11, Identifier12, Identifier13, Identifier14, Identifier15 }).Replace("-", "");
            }
            [StructLayout(LayoutKind.Sequential)]
            public struct FILE_ID_INFO { public ulong VolumeSerialNumber; public FILE_ID_128 FileId; }
            [DllImport("kernel32.dll", SetLastError = true)]
            private static extern bool GetFileInformationByHandleEx(IntPtr hFile, int FileInformationClass, out FILE_ID_INFO lpFileInformation, uint dwBufferSize);
            private const int FileIdInfo = 0x12;
            public static string GetUniqueFileId(string path)
            {
                if (string.IsNullOrEmpty(path) || !File.Exists(path)) return null;
                try
                {
                    using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                    {
                        FILE_ID_INFO info;
                        if (GetFileInformationByHandleEx(fs.SafeFileHandle.DangerousGetHandle(), FileIdInfo, out info, (uint)Marshal.SizeOf(typeof(FILE_ID_INFO))))
                            return $"{info.VolumeSerialNumber:X}-{info.FileId}";
                    }
                }
                catch { return null; }
                return null;
            }
        }

        // --- Global State ---
        private static Dictionary<int, string> processIdToExeName = new Dictionary<int, string>();
        private static Dictionary<int, int> childToParent = new Dictionary<int, int>();
        private static Dictionary<int, string> processToImagePath = new Dictionary<int, string>();
        private static HashSet<int> scannedPids = new HashSet<int>(); // 避免重複掃描同一 PID

        // [NEW] Behavior Tracking
        enum BehaviorType { FileAccess, RegistryAccess, MemoryScan }
        private static Dictionary<int, HashSet<BehaviorType>> processBehaviors = new Dictionary<int, HashSet<BehaviorType>>();

        private static bool answerSent = false;
        private static string TargetFileId = null;

        static async Task Main(string[] args)
        {
            string targetPath = @"C:\Users\bombe\AppData\Local\bhrome\Login Data";
            TargetFileId = FileIdHelper.GetUniqueFileId(targetPath);
            Console.WriteLine($"[EDR Init] Target File ID: {TargetFileId ?? "NOT FOUND"}");

            // Start Kernel Session (File, Reg, Process)
            var kernelTask = Task.Run(() =>
            {
                using (var kernelSession = new TraceEventSession(KernelTraceEventParser.KernelSessionName))
                {
                    Console.CancelKeyPress += delegate (object sender, ConsoleCancelEventArgs e) { kernelSession.Dispose(); };

                    Task.Run(() => ScanLoop());

                    Console.CancelKeyPress += delegate { kernelSession.Dispose(); };
                    kernelSession.EnableKernelProvider(
                        KernelTraceEventParser.Keywords.ImageLoad |
                        KernelTraceEventParser.Keywords.Process |
                        KernelTraceEventParser.Keywords.DiskFileIO |
                        KernelTraceEventParser.Keywords.FileIOInit |
                        KernelTraceEventParser.Keywords.FileIO |
                        KernelTraceEventParser.Keywords.Registry
                    );
                    kernelSession.Source.Kernel.ProcessStart += processStartedHandler;
                    kernelSession.Source.Kernel.ProcessStop += processStoppedHandler;
                    kernelSession.Source.Kernel.FileIORead += fileReadHandler;
                    kernelSession.Source.Kernel.ImageLoad += imageLoadHandler;
                    kernelSession.Source.Kernel.RegistryOpen += registryOpenHandler;
                    kernelSession.Source.Process();
                }
            });
            await kernelTask;
        }

        private static void ScanLoop()
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

                    string detection = MemoryScanner.Scan(pid);
                    if (detection != null)
                    {
                        Console.WriteLine($"[ALERT] Malicious Pattern '{detection}' found in PID: {pid}");

                        RecordAndCheckMalware(
                            pid,
                            BehaviorType.MemoryScan,
                            $"Memory pattern: {detection}"
                        );
                    }

                    scannedPids.Add(pid);
                }

                Thread.Sleep(1000);
            }
        }


        // --- Logic to Correlate Behaviors ---
        private static void RecordAndCheckMalware(int sourcePid, BehaviorType type, string details)
        {
            if (answerSent) return;

            // 1. Backtrack to find the ROOT process (BOMBE...)
            int root = sourcePid;
            int safetyCount = 0;

            while (safetyCount < 50)
            {
                safetyCount++;
                string fullFilePath = null;
                lock (processToImagePath) { processToImagePath.TryGetValue(root, out fullFilePath); }

                if (IsTargetMalwareProcess(fullFilePath))
                {
                    // Found a BOMBE candidate
                    lock (processBehaviors)
                    {
                        if (!processBehaviors.ContainsKey(root))
                        {
                            processBehaviors[root] = new HashSet<BehaviorType>();
                            Console.WriteLine($"[Tracking] Process {root} ({Path.GetFileName(fullFilePath)}) started suspicious activity.");
                        }

                        // Add the behavior type
                        if (processBehaviors[root].Add(type))
                        {
                            Console.WriteLine($"   + Behavior Added: {type} | {details}");
                        }

                        // === DECISION LOGIC: 2 or more distinct behaviors ===
                        if (processBehaviors[root].Count >= 2)
                        {
                            string exeName = null;
                            lock (processIdToExeName) { processIdToExeName.TryGetValue(root, out exeName); }
                            if (string.IsNullOrEmpty(exeName)) exeName = Path.GetFileName(fullFilePath);

                            Console.WriteLine("\n=======================================================");
                            Console.WriteLine(" ALARM: Multi-Behavior Correlation Confirmed!");
                            Console.WriteLine($" Real Malware: {exeName} (PID: {root})");
                            Console.WriteLine($" Detected Actions: {string.Join(", ", processBehaviors[root])}");
                            Console.WriteLine("=======================================================\n");

                            answerSent = true;
                            _ = SendAnswerToServer(JsonConvert.SerializeObject(new { answer = exeName, secret = SECRET }));
                        }
                    }
                    break; // Stop backtracking, we found the owner
                }

                // Move up tree
                int parentId;
                bool hasParent;
                lock (childToParent) { hasParent = childToParent.TryGetValue(root, out parentId); }
                if (!hasParent || parentId == root || parentId == 0) break;
                root = parentId;
            }
        }

        private static void fileReadHandler(FileIOReadWriteTraceData data)
        {
            try
            {
                if (answerSent || string.IsNullOrEmpty(TargetFileId)) return;

                // Check File ID (bypasses Hard Links)
                string currentFileId = FileIdHelper.GetUniqueFileId(data.FileName);

                if (!string.IsNullOrEmpty(currentFileId) && currentFileId == TargetFileId)
                {
                    RecordAndCheckMalware(data.ProcessID, BehaviorType.FileAccess, $"Read File: {data.FileName}");
                }
            }
            catch { }
        }

        private static void registryOpenHandler(RegistryTraceData data)
        {
            try
            {
                if (answerSent) return;
                if (!string.IsNullOrEmpty(data.KeyName) && data.KeyName.ToUpper().Contains("SOFTWARE\\BOMBE"))
                {
                    RecordAndCheckMalware(data.ProcessID, BehaviorType.RegistryAccess, $"Opened Key: {data.KeyName}");
                }
            }
            catch { }
        }

        // --- Helpers (Process Tracking, etc.) ---

        private static bool IsTargetMalwareProcess(string imageNameOrPath)
        {
            if (string.IsNullOrEmpty(imageNameOrPath)) return false;
            return Path.GetFileName(imageNameOrPath).StartsWith("BOMBE", StringComparison.OrdinalIgnoreCase);
        }

        private static void imageLoadHandler(ImageLoadTraceData data)
        {
            if (!data.FileName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) return;
            lock (processToImagePath)
            {
                if (processToImagePath.TryGetValue(data.ProcessID, out string existing))
                    if (!string.IsNullOrEmpty(existing) && existing.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) return;

                lock (processIdToExeName)
                {
                    if (processIdToExeName.TryGetValue(data.ProcessID, out string shortName) &&
                        !string.IsNullOrEmpty(shortName) && data.FileName.EndsWith(shortName, StringComparison.OrdinalIgnoreCase))
                        processToImagePath[data.ProcessID] = data.FileName;
                    else
                        processToImagePath[data.ProcessID] = data.FileName;
                }
            }
        }

        private static async void processStartedHandler(ProcessTraceData data)
        {
            lock (processIdToExeName) { processIdToExeName[data.ProcessID] = data.ImageFileName; }
            lock (childToParent) { childToParent[data.ProcessID] = data.ParentID; }
        }

        private static void processStoppedHandler(ProcessTraceData data)
        {
            lock (processIdToExeName) { processIdToExeName.Remove(data.ProcessID); }
            // Optional: Remove from tracking to free memory, but beware if events come in late
            lock (processBehaviors) { processBehaviors.Remove(data.ProcessID); }
        }

        private static async Task SendAnswerToServer(string jsonPayload)
        {
            using (HttpClient client = new HttpClient())
            {
                try
                {
                    StringContent content = new StringContent(jsonPayload, Encoding.UTF8, "application/json");
                    HttpResponseMessage response = await client.PostAsync("https://submit.bombe.top/submitEdrAns", content);
                    response.EnsureSuccessStatusCode();
                    Console.WriteLine($"[Server] {await response.Content.ReadAsStringAsync()}");
                }
                catch (Exception e) { Console.WriteLine($"[Network Error] {e.Message}"); }
            }
        }
    }
}