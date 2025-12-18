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
using System.Xml.Linq;

namespace EDRPOC
{
    internal class Program
    {
        const string SECRET = "00000000000000000000000000000000";

        public static class FileIdHelper
        {
            // 定義結構：用來存放 128-bit 的檔案 ID
            [StructLayout(LayoutKind.Sequential)]
            public struct FILE_ID_128
            {
                public byte Identifier0; public byte Identifier1; public byte Identifier2; public byte Identifier3;
                public byte Identifier4; public byte Identifier5; public byte Identifier6; public byte Identifier7;
                public byte Identifier8; public byte Identifier9; public byte Identifier10; public byte Identifier11;
                public byte Identifier12; public byte Identifier13; public byte Identifier14; public byte Identifier15;

                // 覆寫 ToString 方便比對與印出
                public override string ToString()
                {
                    return BitConverter.ToString(new byte[] {
                Identifier0, Identifier1, Identifier2, Identifier3,
                Identifier4, Identifier5, Identifier6, Identifier7,
                Identifier8, Identifier9, Identifier10, Identifier11,
                Identifier12, Identifier13, Identifier14, Identifier15
            }).Replace("-", "");
                }
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct FILE_ID_INFO
            {
                public ulong VolumeSerialNumber; // 磁碟區序號
                public FILE_ID_128 FileId;       // 檔案唯一 ID
            }

            // API 定義
            [DllImport("kernel32.dll", SetLastError = true)]
            private static extern bool GetFileInformationByHandleEx(
                IntPtr hFile,
                int FileInformationClass, // 0x12 = FileIdInfo
                out FILE_ID_INFO lpFileInformation,
                uint dwBufferSize);

            private const int FileIdInfo = 0x12;

            /// <summary>
            /// 取得指定路徑檔案的唯一 ID (包含 VolumeSerial + FileId)
            /// </summary>
            public static string GetUniqueFileId(string path)
            {
                if (string.IsNullOrEmpty(path) || !File.Exists(path)) return null;

                try
                {
                    // 開啟檔案以讀取屬性 (不需讀取內容權限，這樣比較不會被鎖住)
                    using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                    {
                        FILE_ID_INFO info;
                        if (GetFileInformationByHandleEx(fs.SafeFileHandle.DangerousGetHandle(), FileIdInfo, out info, (uint)Marshal.SizeOf(typeof(FILE_ID_INFO))))
                        {
                            // 回傳組合字串: "VolumeSerial-FileId"
                            return $"{info.VolumeSerialNumber:X}-{info.FileId}";
                        }
                    }
                }
                catch (Exception)
                {
                    // 檔案可能被獨佔鎖定，或是權限不足
                    return null;
                }
                return null;
            }
        }

        // Dictionary to store process ID to executable filename mapping
        private static Dictionary<int, string> processIdToExeName = new Dictionary<int, string>();
        private static Dictionary<int, int> childToParent = new Dictionary<int, int>();
        private static Dictionary<int, string> processToImagePath = new Dictionary<int, string>();

        // Flag to ensure the answer is sent only once
        private static bool answerSent = false;
        private static string TargetFileId = null;
        static async Task Main(string[] args)
        {
            // 1. [初始化] 在開始監控前，先計算出目標檔案的 File ID
            string targetPath = @"C:\Users\bombe\AppData\Local\bhrome\Login Data";

            // 注意：如果檔案這時候不存在，EDR 可能需要處理例外，或是等檔案建立後再抓
            TargetFileId = FileIdHelper.GetUniqueFileId(targetPath);

            Console.WriteLine($"[EDR Init] Target File ID: {TargetFileId}");
            if (TargetFileId == null)
            {
                Console.WriteLine("[Warning] Cannot access target file to get ID. Is path correct?");
            }

            using (var kernelSession = new TraceEventSession(KernelTraceEventParser.KernelSessionName))
            {
                Console.CancelKeyPress += delegate (object sender, ConsoleCancelEventArgs e) { kernelSession.Dispose(); };

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
                //kernelSession.Source.Kernel.RegistryQueryValue += registryQueryHandler;
                kernelSession.Source.Kernel.RegistryOpen += registryOpenHandler;


                kernelSession.Source.Process();
            }
        }
        private static bool IsTrustedSystemLocation(string fullFilePath)
        {
            if (string.IsNullOrEmpty(fullFilePath)) return false;

            string system32 = Environment.SystemDirectory;
            string syswow64 = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SysWOW64");

            string path = fullFilePath.ToLower();

            return path.StartsWith(system32.ToLower()) || path.StartsWith(syswow64.ToLower());
        }
        private static bool IsTargetMalwareProcess(string imageNameOrPath)
        {
            if (string.IsNullOrEmpty(imageNameOrPath)) return false;
            string fileName = Path.GetFileName(imageNameOrPath);

            return fileName.StartsWith("BOMBE", StringComparison.OrdinalIgnoreCase);
        }
        private static void imageLoadHandler(ImageLoadTraceData data)
        {
            if (!data.FileName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) return;
            lock (processToImagePath)
            {
                // 防止dll覆蓋掉.exe路徑
                if (processToImagePath.TryGetValue(data.ProcessID, out string existingPath))
                {
                    if (!string.IsNullOrEmpty(existingPath) &&
                        existingPath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                    {
                        return;
                    }
                }

                // 只有當載入的檔名跟 Process 名稱吻合時才記錄
                lock (processIdToExeName)
                {
                    if (processIdToExeName.TryGetValue(data.ProcessID, out string shortName))
                    {
                        if (!string.IsNullOrEmpty(shortName) &&
                            data.FileName.EndsWith(shortName, StringComparison.OrdinalIgnoreCase))
                        {
                            processToImagePath[data.ProcessID] = data.FileName;
                        }
                    }
                    else
                    {
                        processToImagePath[data.ProcessID] = data.FileName;
                    }
                }
            }
        }
        private static void processStartedHandler(ProcessTraceData data)
        {
            lock (processIdToExeName)
            {
                processIdToExeName[data.ProcessID] = data.ImageFileName;
            }
            lock (childToParent)
            {
                childToParent[data.ProcessID] = data.ParentID;
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
            try
            {
                // Check if the answer has already been sent
                //if (answerSent) return;

                // Define the full path to the target file
                //string targetFilePath = ("C:\\Users\\bombe\\AppData\\Local\\bhrome\\Login Data").ToLower();

                //if (data.FileName.ToLower().Equals(targetFilePath))
                if (string.IsNullOrEmpty(TargetFileId)) return;
                string currentFileId = FileIdHelper.GetUniqueFileId(data.FileName);
                Console.WriteLine($"[Read] Target File ID: {currentFileId}");

                // 3. 比對 ID (這就是 Hard Link 絕對繞不過去的地方)
                if (!string.IsNullOrEmpty(TargetFileId) &&
                    !string.IsNullOrEmpty(currentFileId) &&
                    currentFileId == TargetFileId) // ID 相同！
                {
                    Console.WriteLine("TargetFileId==currentFileId");
                    // root backtracking
                    int root = data.ProcessID;
                    while (true)
                    {
                        string imagePath = null;
                        lock (processToImagePath) { processToImagePath.TryGetValue(root, out imagePath); }
                        if (IsTargetMalwareProcess(imagePath))
                        {
                            Console.WriteLine("Yes, start with BOMBE");
                            // classified to malware
                            string exeName = null;
                            lock (processIdToExeName) { processIdToExeName.TryGetValue(root, out exeName); }
                            Console.WriteLine("---------------------File Read-----------------------------");
                            Console.WriteLine("File read: {0},\nprocess: {1}", data.FileName, data.ProcessName);
                            Console.WriteLine("Real malware: {0},\nwith pid {1},\nimagePath: {2}", exeName, root, imagePath);
                            Console.WriteLine("------------------------------------------------------");

                            // Send the executable filename to the server
                            if (!string.IsNullOrEmpty(exeName))
                            {
                                // Set the flag to true to disable further handling
                                answerSent = true;

                                await SendAnswerToServer(JsonConvert.SerializeObject(
                                    new
                                    {
                                        answer = exeName,
                                        secret = SECRET
                                    }
                                ));

                            }
                            break;
                        }
                        lock (childToParent) { childToParent.TryGetValue(root, out root); }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Error in fileReadHandler] {ex.Message}");
                Console.WriteLine(ex.StackTrace);
            }
        }
        private static async void registryOpenHandler(RegistryTraceData data)
        {
            try
            {
                // Check if the answer has already been sent
                //if (answerSent) return;

                if (!string.IsNullOrEmpty(data.KeyName) && data.KeyName.ToUpper().Contains("SOFTWARE\\BOMBE"))
                {
                    // root backtracking
                    int root = data.ProcessID;
                    while (true)
                    {
                        string fullFilePath = null;
                        lock (processToImagePath) { processToImagePath.TryGetValue(root, out fullFilePath); }
                        if (IsTargetMalwareProcess(fullFilePath))
                        {
                            // classified to malware
                            string exeName = null;
                            lock (processIdToExeName) { processIdToExeName.TryGetValue(root, out exeName); }
                            Console.WriteLine("---------------------Registry Open-----------------------------");
                            Console.WriteLine("Key read: {0},\nprocess: {1}", data.KeyName, data.ProcessName);
                            Console.WriteLine("Real malware: {0},\nwith pid {1},\nimagePath: {2}", exeName, root, fullFilePath);
                            Console.WriteLine("------------------------------------------------------");

                            // Send the executable filename to the server
                            if (!string.IsNullOrEmpty(exeName))
                            {
                                // Set the flag to true to disable further handling
                                answerSent = true;

                                await SendAnswerToServer(JsonConvert.SerializeObject(
                                    new
                                    {
                                        answer = exeName,
                                        secret = SECRET
                                    }
                                ));

                            }
                            break;
                        }
                        lock (childToParent) { childToParent.TryGetValue(root, out root); }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Error in registryQueryHandler] {ex.Message}");
                Console.WriteLine(ex.StackTrace);
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
