using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace EDRPOC
{
    internal class Program
    {
        const string SECRET = "0000";

        // Dictionary to store process ID to executable filename mapping
        private static Dictionary<int, string> processIdToExeName = new Dictionary<int, string>();
        private static Dictionary<int, int> childToParent = new Dictionary<int, int>();
        private static Dictionary<int, string> processToImagePath = new Dictionary<int, string>();

        // Flag to ensure the answer is sent only once
        private static bool answerSent = false;

        static async Task Main(string[] args)
        {
            using (var kernelSession = new TraceEventSession(KernelTraceEventParser.KernelSessionName))
            {
                Console.CancelKeyPress += delegate (object sender, ConsoleCancelEventArgs e) { kernelSession.Dispose(); };

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
                kernelSession.Source.Kernel.ImageLoad += imageLoadHandler;


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

        private static void imageLoadHandler(ImageLoadTraceData data)
        {
            lock (processToImagePath)
            {
                processToImagePath[data.ProcessID] = data.FileName;
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
                if (answerSent) return;

                // Define the full path to the target file
                string targetFilePath = ("C:\\Users\\bombe\\AppData\\Local\\bhrome\\Login Data").ToLower();

                if (data.FileName.ToLower().Equals(targetFilePath))
                {
                    // root backtracking
                    int root = data.ProcessID;
                    while (true)
                    {
                        string fullFilePath = null;
                        lock (processToImagePath) { processToImagePath.TryGetValue(root, out fullFilePath); }
                        if (!IsTrustedSystemLocation(fullFilePath))
                        {
                            // classified to malware
                            string exeName = null;
                            lock (processIdToExeName) { processIdToExeName.TryGetValue(root, out exeName); }
                            Console.WriteLine("File read: {0},\nprocess: {1}", data.FileName, data.ProcessName);
                            Console.WriteLine("Real malware: {0},\nwith pid {1},\nimagePath: {2}", exeName, root, fullFilePath);
                            Console.WriteLine("------------------------------------------------------");

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
