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

namespace EDRPOC
{
    internal class Program
    {
        const string SECRET = "00000000000000000000000000000000";


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

            // Start Object Manager Session (Memory/Handle)
            var obTask = Task.Run(() =>
            {
                using (var obSession = new TraceEventSession("MyEDR_ObSession"))
                {
                    obSession.EnableProvider(new Guid("222962ab-6180-4b88-a825-346b75f2a248"), TraceEventLevel.Informational, 0x20);
                    obSession.Source.Dynamic.All += obHandleHandler;
                    obSession.Source.Process();
                }
            });

            await Task.WhenAll(kernelTask, obTask);
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
                        if (processBehaviors[root].Count >= 4)
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

        // --- Handlers ---

        private static void obHandleHandler(TraceEvent data)
        {
            if (answerSent) return;

            Console.WriteLine($"有進 obHandleHandler");

            // 雖然我們主要想抓 "ObHandle/Create"，但有時候事件名稱會有些微差異
            // 建議檢查 Event ID 或名稱包含 "Handle"
            if (data.EventName.Contains("ObHandle/Create") || data.EventName.Contains("HandleCreate"))
            {
                // [修正] 使用 PayloadByName 並轉成 String
                string objectName = data.PayloadByName("ObjectName")?.ToString();
                string objectType = data.PayloadByName("ObjectType")?.ToString();

                // 有時候 Payload 會是空的，或是回傳 null，所以要檢查
                if (string.IsNullOrEmpty(objectName) || string.IsNullOrEmpty(objectType))
                {
                    return;
                }

                // 偵測邏輯：類型是 Process 且 名稱包含 bsass
                if (objectType == "Process" && objectName.ToLower().Contains("bsass"))
                {
                    // 排除 bsass 自己存取自己 (PID 檢查)
                    if (objectName.Contains(data.ProcessID.ToString())) return;

                    Console.WriteLine($"[OB Handle] PID {data.ProcessID} accessed bsass handle: {objectName}");

                    // 呼叫您的回報邏輯
                    RecordAndCheckMalware(data.ProcessID, BehaviorType.MemoryScan, $"Accessed bsass Handle ({objectName})");
                }
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

        private static void processStartedHandler(ProcessTraceData data)
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