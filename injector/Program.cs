using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Threading;

namespace Injector
{
    class Program
    {

        // Constants
        const int PROCESS_ALL_ACCESS = 0x1F0FFF;
        const int THREAD_SUSPEND_RESUME = 0x0002;

        // Helper function for logging
        private static void LogToFile(string message)
        {
            try
            {
                string timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
                string logMessage = $"[{timestamp}] {message}";
                
                // Also output to console
                Console.WriteLine(message);
                
                // Write to log file in current directory
                string logPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "injector_log.txt");
                File.AppendAllText(logPath, logMessage + Environment.NewLine);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Warning: Failed to write to log file: {ex.Message}");
            }
        }

        // Entry point
        static void Main(string[] args)
        {
            // Set up logging
            string logPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "injector_log.txt");
            File.AppendAllText(logPath, $"\n=== Injector Started ===\nArguments: {string.Join(" ", args)}\nWorking Directory: {Environment.CurrentDirectory}\nExecutable Path: {AppDomain.CurrentDomain.BaseDirectory}\n");

            try
            {
                // Parse command line arguments
                int targetPid = -1;
                bool suspendNtdll = true;
                bool permanentSuspension = true;
                int suspensionDuration = 0;
                List<string> dllsToSuspend = new List<string>();

                if (args.Length > 0)
                {
                    if (int.TryParse(args[0], out int pid))
                    {
                        targetPid = pid;
                    }
                    else
                    {
                        Console.WriteLine("Invalid PID. Using default Roblox process.");
                        targetPid = FindRobloxProcess();
                    }

                    // Parse suspension options
                    if (args.Length > 1)
                    {
                        string suspensionArg = args[1].ToLower();
                        if (suspensionArg == "false" || suspensionArg == "none")
                        {
                            suspendNtdll = false;
                        }
                        else if (suspensionArg == "timed")
                        {
                            suspendNtdll = true;
                            permanentSuspension = false;
                            if (args.Length > 2 && int.TryParse(args[2], out int duration))
                            {
                                suspensionDuration = duration;
                            }
                            else
                            {
                                suspensionDuration = 5000; // Default 5 seconds
                            }
                        }
                        else if (suspensionArg == "permanent" || suspensionArg == "true")
                        {
                            suspendNtdll = true;
                            permanentSuspension = true;
                        }
                    }

                    // Parse additional DLLs to suspend
                    for (int i = 2; i < args.Length; i++)
                    {
                        if (args[i].StartsWith("--suspend:"))
                        {
                            string dllName = args[i].Substring(10);
                            dllsToSuspend.Add(dllName);
                        }
                    }
                }
                else
                {
                    // Default behavior: find Roblox and use permanent ntdll suspension
                    targetPid = FindRobloxProcess();
                    suspendNtdll = true;
                    permanentSuspension = true;
                }

                if (targetPid == -1)
                {
                    Console.WriteLine("No target process found.");
                    File.AppendAllText(logPath, "ERROR: No target process found.\n");
                    return;
                }

                Console.WriteLine($"Target PID: {targetPid}");
                File.AppendAllText(logPath, $"Target PID: {targetPid}\n");

                // Get DLL path
                string dllPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "cat.dll");
                Console.WriteLine($"Looking for DLL at: {dllPath}");
                File.AppendAllText(logPath, $"Looking for DLL at: {dllPath}\n");

                if (!File.Exists(dllPath))
                {
                    Console.WriteLine("DLL not found!");
                    File.AppendAllText(logPath, "ERROR: DLL not found!\n");
                    return;
                }

                Console.WriteLine("Attempting DLL injection...");
                File.AppendAllText(logPath, "Attempting DLL injection...\n");

                // Determine injection strategy based on process type
                bool isRobloxProcess = IsRobloxProcess(targetPid);
                bool isProtectedProcess = IsProtectedProcess(targetPid);
                bool injectionSuccess = false;

                // For Roblox, ALWAYS enable ntdll suspension (required for proper injection)
                if (isRobloxProcess)
                {
                    suspendNtdll = true;
                    if (!permanentSuspension && suspensionDuration == 0)
                    {
                        permanentSuspension = true; // Default to permanent for Roblox
                    }
                }

                if (isRobloxProcess)
                {
                    Console.WriteLine("Detected Roblox process, using simple injection with targeted ntdll suspension...");
                    File.AppendAllText(logPath, "Using simple injection for Roblox with targeted ntdll suspension to bypass anti-cheat.\n");
                    
                    // For Roblox, use simple LoadLibraryA injection first (like the working version)
                    Console.WriteLine("Using simple LoadLibraryA injection for Roblox...");
                    injectionSuccess = LoadLibraryInject(targetPid, dllPath);
                    
                    if (injectionSuccess)
                    {
                        Console.WriteLine("DLL injected successfully! Now suspending ntdll.dll threads to bypass anti-cheat...");
                        // Use targeted ntdll suspension AFTER injection (like the working version)
                        SuspendTargetedNtdllThreads(targetPid);
                        Console.WriteLine("Targeted ntdll.dll threads suspended.");
                    }
                    else
                    {
                        Console.WriteLine("Simple injection failed, trying stealth injection...");
                        injectionSuccess = ManualMapper.StealthInjectForRoblox(targetPid, dllPath);
                        if (injectionSuccess)
                        {
                            SuspendTargetedNtdllThreads(targetPid);
                        }
                    }
                }
                else if (isProtectedProcess)
                {
                    Console.WriteLine("Detected protected process, using manual mapping with thread suspension...");
                    File.AppendAllText(logPath, "Using manual mapping for protected process.\n");
                    
                    // Suspend threads before injection for protected processes
                    if (suspendNtdll)
                    {
                        SuspendNtdllThreads(targetPid, permanentSuspension, suspensionDuration);
                    }
                    
                    foreach (string dllName in dllsToSuspend)
                    {
                        SuspendDllThreads(targetPid, dllName, permanentSuspension, suspensionDuration);
                    }
                    
                    injectionSuccess = ManualMapper.ManualMapDll(targetPid, dllPath);
                }
                else
                {
                    Console.WriteLine("Using standard LoadLibraryA injection...");
                    File.AppendAllText(logPath, "Using standard LoadLibraryA injection.\n");
                    
                    injectionSuccess = ManualMapper.LoadLibraryInject(targetPid, dllPath);
                }

                if (injectionSuccess)
                {
                    Console.WriteLine("DLL injected successfully!");
                    File.AppendAllText(logPath, "DLL injected successfully!\n");
                    
                    // Verify DLL was loaded
                    Console.WriteLine("Verifying DLL was loaded...");
                    if (IsDllLoaded(targetPid, "cat.dll"))
                    {
                        Console.WriteLine("DLL verification successful!");
                        File.AppendAllText(logPath, "DLL verification successful!\n");
                    }
                    else
                    {
                        Console.WriteLine("Warning: Could not verify DLL loading");
                        File.AppendAllText(logPath, "Warning: Could not verify DLL loading\n");
                    }
                    
                    Console.WriteLine("Check for a message box from the target process.");
                    File.AppendAllText(logPath, "Injection completed successfully.\n");
                }
                else
                {
                    Console.WriteLine("DLL injection failed!");
                    File.AppendAllText(logPath, "ERROR: DLL injection failed!\n");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
                File.AppendAllText(logPath, $"ERROR: {ex.Message}\n");
            }
        }

        private static bool IsRobloxProcess(int processId)
        {
            try
            {
                var process = System.Diagnostics.Process.GetProcessById(processId);
                string processName = process.ProcessName.ToLower();
                
                // Check if this is a Roblox process
                string[] robloxProcesses = {
                    "robloxplayerbeta",
                    "roblox",
                    "windows10universal"
                };
                
                return robloxProcesses.Any(name => processName.Contains(name));
            }
            catch
            {
                return false;
            }
        }

        private static bool IsProtectedProcess(int processId)
        {
            try
            {
                var process = System.Diagnostics.Process.GetProcessById(processId);
                string processName = process.ProcessName.ToLower();
                
                // List of processes that typically need manual mapping (excluding Roblox which has its own method)
                string[] protectedProcesses = {
                    "fortniteclient-win64-shipping",
                    "csgo",
                    "valorant",
                    "leagueoflegends",
                    "overwatch",
                    "apexlegends"
                };
                
                return protectedProcesses.Any(name => processName.Contains(name));
            }
            catch
            {
                return false;
            }
        }

        private static int FindRobloxProcess()
        {
            try
            {
                string[] processNames = { "RobloxPlayerBeta", "Roblox", "Windows10Universal" };
                
                foreach (string processName in processNames)
                {
                    var processes = System.Diagnostics.Process.GetProcessesByName(processName);
                    if (processes.Length > 0)
                    {
                        return processes[0].Id;
                    }
                }
                
                return -1;
            }
            catch
            {
                return -1;
            }
        }

        private static void SuspendNtdllThreads(int processId, bool permanent, int duration)
        {
            try
            {
                Console.WriteLine("Suspending threads in ntdll.dll...");
                SuspendDllThreads(processId, "ntdll.dll", permanent, duration);
                Console.WriteLine("Threads in ntdll.dll suspended.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Warning: Failed to suspend ntdll threads: {ex.Message}");
            }
        }

        private static void SuspendDllThreads(int processId, string dllName, bool permanent, int duration)
        {
            try
            {
                IntPtr hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, processId);
                if (hProcess == IntPtr.Zero)
                {
                    throw new Exception($"Failed to open process. Error: {GetLastError()}");
                }

                var threads = GetProcessThreads(processId);
                int suspendedCount = 0;
                int maxThreadsToSuspend = 5; // Limit to avoid freezing

                // For Roblox, be more conservative with thread suspension
                bool isRoblox = IsRobloxProcess(processId);
                if (isRoblox)
                {
                    maxThreadsToSuspend = 3; // Suspend a few more threads for Roblox to ensure anti-cheat bypass
                    Console.WriteLine("Using targeted thread suspension for Roblox anti-cheat bypass");
                }

                foreach (var thread in threads)
                {
                    if (suspendedCount >= maxThreadsToSuspend)
                    {
                        Console.WriteLine($"Reached max thread suspension limit ({maxThreadsToSuspend}) for safety");
                        break;
                    }

                    try
                    {
                        IntPtr hThread = OpenThread(ThreadAccess.SUSPEND_RESUME, false, (uint)thread.Id);
                        if (hThread != IntPtr.Zero)
                        {
                            if (SuspendThread(hThread) != -1)
                            {
                                suspendedCount++;
                                Console.WriteLine($"Suspended thread {thread.Id} in {dllName}");
                            }
                            CloseHandle(hThread);
                        }
                    }
                    catch
                    {
                        // Continue with other threads
                    }
                }

                Console.WriteLine($"Suspended {suspendedCount} threads in {dllName}");

                if (!permanent && duration > 0)
                {
                    Task.Run(() =>
                    {
                        Thread.Sleep(duration);
                        ResumeDllThreads(processId, dllName);
                    });
                }
                // Note: Removed auto-resume for Roblox since we're using timed suspension
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to suspend threads in {dllName}: {ex.Message}");
            }
        }

        private static void ResumeDllThreads(int processId, string dllName)
        {
            try
            {
                IntPtr hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, processId);
                if (hProcess == IntPtr.Zero) return;

                var threads = GetProcessThreads(processId);
                int resumedCount = 0;

                foreach (var thread in threads)
                {
                    try
                    {
                        IntPtr hThread = OpenThread(ThreadAccess.SUSPEND_RESUME, false, (uint)thread.Id);
                        if (hThread != IntPtr.Zero)
                        {
                            if (ResumeThread(hThread) != -1)
                            {
                                resumedCount++;
                            }
                            CloseHandle(hThread);
                        }
                    }
                    catch
                    {
                        // Continue with other threads
                    }
                }

                Console.WriteLine($"Resumed {resumedCount} threads in {dllName}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to resume threads in {dllName}: {ex.Message}");
            }
        }

        private static List<ProcessThread> GetProcessThreads(int processId)
        {
            var threads = new List<ProcessThread>();
            try
            {
                var process = System.Diagnostics.Process.GetProcessById(processId);
                foreach (ProcessThread thread in process.Threads)
                {
                    threads.Add(thread);
                }
            }
            catch
            {
                // Return empty list if process not found
            }
            return threads;
        }

        private static bool IsDllLoaded(int processId, string dllName)
        {
            try
            {
                var process = System.Diagnostics.Process.GetProcessById(processId);
                foreach (ProcessModule module in process.Modules)
                {
                    if (module.ModuleName.ToLower() == dllName.ToLower())
                    {
                        return true;
                    }
                }
                return false;
            }
            catch
            {
                return false;
            }
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll")]
        static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        [DllImport("ntdll.dll")]
        private static extern int NtQueryInformationThread(IntPtr ThreadHandle, int ThreadInformationClass,
            IntPtr ThreadInformation, int ThreadInformationLength, IntPtr ReturnLength);

        [DllImport("kernel32.dll")]
        static extern uint SuspendThread(IntPtr hThread);

        [DllImport("kernel32.dll")]
        static extern uint GetLastError();

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint ResumeThread(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll")]
        static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetExitCodeThread(IntPtr hThread, out uint lpExitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint dwFreeType);

        [Flags]
        public enum ThreadAccess : int
        {
            SUSPEND_RESUME = 0x0002,
            QUERY_INFORMATION = 0x0040
        }

        static void InjectDll(int pid, string dllPath)
        {
            LogToFile($"Manual mapping DLL into process {pid}...");
            
            bool success = ManualMapper.ManualMapDll(pid, dllPath);
            
            if (success)
            {
                LogToFile("Manual mapping completed successfully!");
                
                // Verify DLL was loaded by checking process modules
                LogToFile("Verifying DLL was loaded...");
                try
                {
                    var targetProcess = Process.GetProcessById(pid);
                    bool dllFound = false;
                    foreach (ProcessModule module in targetProcess.Modules)
                    {
                        if (module.ModuleName.ToLower().Contains("cat.dll"))
                        {
                            LogToFile($"DLL found in process: {module.ModuleName} at 0x{module.BaseAddress:X}");
                            dllFound = true;
                            break;
                        }
                    }
                    if (!dllFound)
                    {
                        LogToFile("Note: cat.dll may not appear in module list with manual mapping (this is normal)");
                    }
                }
                catch (Exception ex)
                {
                    LogToFile($"Warning: Could not verify DLL loading: {ex.Message}");
                }
            }
            else
            {
                throw new Exception("Manual mapping failed");
            }
        }

        static void SuspendThreadsInDll(int pid, string dllName, bool permanent)
        {
            var process = Process.GetProcessById(pid);
            List<IntPtr> suspendedThreads = new List<IntPtr>();

            foreach (ProcessThread thread in process.Threads)
            {
                try
                {
                    IntPtr hThread = OpenThread(ThreadAccess.SUSPEND_RESUME | ThreadAccess.QUERY_INFORMATION, false, (uint)thread.Id);
                    if (hThread == IntPtr.Zero) continue;

                    const int ThreadQuerySetWin32StartAddress = 9;
                    IntPtr startAddressPtr = Marshal.AllocHGlobal(IntPtr.Size);
                    NtQueryInformationThread(hThread, ThreadQuerySetWin32StartAddress, startAddressPtr, IntPtr.Size, IntPtr.Zero);
                    IntPtr startAddress = Marshal.ReadIntPtr(startAddressPtr);
                    Marshal.FreeHGlobal(startAddressPtr);
                    
                    if (IsAddressInDll(pid, dllName, startAddress))
                    {
                        SuspendThread(hThread);
                        suspendedThreads.Add(hThread);
                        LogToFile($"Suspended thread {thread.Id} in {dllName}");
                    }
                }
                catch (Exception ex)
                {
                    LogToFile($"Warning: Failed to suspend thread {thread.Id}: {ex.Message}");
                }
            }

            LogToFile($"Suspended {suspendedThreads.Count} threads in {dllName}");

            // If not permanent, start a background task to resume threads after a delay
            if (!permanent)
            {
                // For now, we'll just log that temporary suspension is not fully implemented
                // In a full implementation, you would start a background thread to resume after X seconds
                LogToFile($"Note: Temporary suspension not fully implemented. Threads will remain suspended.");
            }
        }

        static bool IsAddressInDll(int pid, string dllName, IntPtr address)
        {
            var process = Process.GetProcessById(pid);
            foreach (ProcessModule module in process.Modules)
            {
                if (module.ModuleName.ToLower().Contains(dllName.ToLower()))
                {
                    IntPtr baseAddr = module.BaseAddress;
                    IntPtr endAddr = (IntPtr)((long)baseAddr + module.ModuleMemorySize);

                    if ((ulong)address.ToInt64() >= (ulong)baseAddr.ToInt64() &&
                        (ulong)address.ToInt64() <= (ulong)endAddr.ToInt64())
                        return true;
                }
            }
            return false;
        }

        // Targeted ntdll suspension method based on the working version
        static void SuspendTargetedNtdllThreads(int processId)
        {
            try
            {
                var process = Process.GetProcessById(processId);
                int suspendedCount = 0;

                foreach (ProcessThread thread in process.Threads)
                {
                    try
                    {
                        IntPtr hThread = OpenThread(ThreadAccess.SUSPEND_RESUME | ThreadAccess.QUERY_INFORMATION, false, (uint)thread.Id);
                        if (hThread == IntPtr.Zero) continue;

                        // Query thread start address
                        const int ThreadQuerySetWin32StartAddress = 9;
                        IntPtr startAddressPtr = Marshal.AllocHGlobal(IntPtr.Size);
                        try
                        {
                            int result = NtQueryInformationThread(hThread, ThreadQuerySetWin32StartAddress, startAddressPtr, IntPtr.Size, IntPtr.Zero);
                            if (result == 0) // STATUS_SUCCESS
                            {
                                IntPtr startAddress = Marshal.ReadIntPtr(startAddressPtr);
                                
                                // Check if this thread starts in ntdll.dll
                                if (IsAddressInNtdll(processId, startAddress))
                                {
                                    uint suspendResult = SuspendThread(hThread);
                                    if (suspendResult != 0xFFFFFFFF) // Not INVALID_HANDLE_VALUE
                                    {
                                        suspendedCount++;
                                        Console.WriteLine($"Suspended ntdll thread {thread.Id} (start: 0x{startAddress:X})");
                                    }
                                }
                            }
                        }
                        finally
                        {
                            Marshal.FreeHGlobal(startAddressPtr);
                            CloseHandle(hThread);
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Error processing thread {thread.Id}: {ex.Message}");
                    }
                }

                Console.WriteLine($"Suspended {suspendedCount} targeted ntdll threads");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to suspend targeted ntdll threads: {ex.Message}");
            }
        }

        // Check if address is within ntdll.dll module
        static bool IsAddressInNtdll(int processId, IntPtr address)
        {
            try
            {
                var process = Process.GetProcessById(processId);
                foreach (ProcessModule module in process.Modules)
                {
                    if (module.ModuleName.ToLower().Contains("ntdll"))
                    {
                        IntPtr baseAddr = module.BaseAddress;
                        IntPtr endAddr = (IntPtr)((long)baseAddr + module.ModuleMemorySize);

                        if ((ulong)address.ToInt64() >= (ulong)baseAddr.ToInt64() &&
                            (ulong)address.ToInt64() <= (ulong)endAddr.ToInt64())
                        {
                            return true;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error checking ntdll address: {ex.Message}");
            }
            return false;
        }

        // Simple LoadLibraryA injection method (like the working version)
        static bool LoadLibraryInject(int processId, string dllPath)
        {
            IntPtr hProcess = IntPtr.Zero;
            IntPtr allocAddress = IntPtr.Zero;
            IntPtr hThread = IntPtr.Zero;

            try
            {
                // Open process
                hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, processId);
                if (hProcess == IntPtr.Zero)
                {
                    Console.WriteLine($"Failed to open process {processId}. Error: {GetLastError()}");
                    return false;
                }

                // Allocate memory for DLL path
                byte[] dllBytes = System.Text.Encoding.ASCII.GetBytes(dllPath + "\0");
                allocAddress = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)dllBytes.Length, 0x1000, 0x04); // MEM_COMMIT, PAGE_READWRITE
                if (allocAddress == IntPtr.Zero)
                {
                    Console.WriteLine($"Failed to allocate memory. Error: {GetLastError()}");
                    return false;
                }

                // Write DLL path to allocated memory
                IntPtr bytesWritten;
                if (!WriteProcessMemory(hProcess, allocAddress, dllBytes, (uint)dllBytes.Length, out bytesWritten))
                {
                    Console.WriteLine($"Failed to write DLL path. Error: {GetLastError()}");
                    return false;
                }

                // Get LoadLibraryA address
                IntPtr loadLibraryAddr = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
                if (loadLibraryAddr == IntPtr.Zero)
                {
                    Console.WriteLine("Failed to get LoadLibraryA address");
                    return false;
                }

                // Create remote thread
                IntPtr threadId;
                hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, loadLibraryAddr, allocAddress, 0, out threadId);
                if (hThread == IntPtr.Zero)
                {
                    Console.WriteLine($"Failed to create remote thread. Error: {GetLastError()}");
                    return false;
                }

                Console.WriteLine($"Created remote thread: {threadId}");

                // Wait for thread completion
                uint waitResult = WaitForSingleObject(hThread, 5000); // 5 second timeout
                if (waitResult == 0) // WAIT_OBJECT_0
                {
                    uint exitCode;
                    if (GetExitCodeThread(hThread, out exitCode))
                    {
                        if (exitCode == 0)
                        {
                            Console.WriteLine("LoadLibraryA returned NULL - injection may have failed");
                            return false;
                        }
                        else
                        {
                            Console.WriteLine($"LoadLibraryA injection successful! HMODULE: 0x{exitCode:X}");
                            return true;
                        }
                    }
                }
                else if (waitResult == 0x102) // WAIT_TIMEOUT
                {
                    Console.WriteLine("LoadLibraryA execution timed out");
                    return false;
                }
                else
                {
                    Console.WriteLine($"Wait failed. Result: {waitResult}");
                    return false;
                }

                return false;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"LoadLibraryA injection failed: {ex.Message}");
                return false;
            }
            finally
            {
                // Cleanup
                if (allocAddress != IntPtr.Zero && hProcess != IntPtr.Zero)
                {
                    VirtualFreeEx(hProcess, allocAddress, 0, 0x8000); // MEM_RELEASE
                }
                if (hThread != IntPtr.Zero)
                {
                    CloseHandle(hThread);
                }
                if (hProcess != IntPtr.Zero)
                {
                    CloseHandle(hProcess);
                }
            }
        }

    }
}
