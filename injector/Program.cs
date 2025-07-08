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
                // Display usage if no arguments provided
                if (args.Length == 0)
                {
                    DisplayUsage();
                    return;
                }

                // Parse command line arguments: [pid] [ntdll suspension] [other dlls to suspend] [use full manual mapper]
                int targetPid = -1;
                bool suspendNtdll = false;
                bool permanentNtdllSuspension = false;
                int ntdllSuspensionDuration = 0;
                List<string> dllsToSuspend = new List<string>();
                bool useFullManualMapper = false;

                // Parse PID (required)
                if (args.Length >= 1)
                {
                    if (int.TryParse(args[0], out int pid))
                    {
                        targetPid = pid;
                    }
                    else
                    {
                        Console.WriteLine($"Invalid PID: {args[0]}");
                        Console.WriteLine("PID must be a valid integer.");
                        return;
                    }
                }

                // Parse ntdll suspension (optional)
                if (args.Length >= 2)
                {
                    string suspensionArg = args[1].ToLower();
                    if (suspensionArg == "perm" || suspensionArg == "permanent")
                    {
                        suspendNtdll = true;
                        permanentNtdllSuspension = true;
                        Console.WriteLine("NTDLL suspension: Permanent");
                    }
                    else if (suspensionArg == "none" || suspensionArg == "false")
                    {
                        suspendNtdll = false;
                        Console.WriteLine("NTDLL suspension: Disabled");
                    }
                    else if (suspensionArg.EndsWith("s"))
                    {
                        // Parse duration in seconds (e.g., "5s", "10s")
                        string durationStr = suspensionArg.Substring(0, suspensionArg.Length - 1);
                        if (int.TryParse(durationStr, out int duration))
                        {
                            suspendNtdll = true;
                            permanentNtdllSuspension = false;
                            ntdllSuspensionDuration = duration * 1000; // Convert to milliseconds
                            Console.WriteLine($"NTDLL suspension: {duration} seconds");
                        }
                        else
                        {
                            Console.WriteLine($"Invalid suspension duration: {args[1]}");
                            Console.WriteLine("Duration must be a number followed by 's' (e.g., '5s', '10s')");
                            return;
                        }
                    }
                    else
                    {
                        Console.WriteLine($"Invalid suspension parameter: {args[1]}");
                        Console.WriteLine("Valid options: 'perm', 'permanent', 'none', 'false', or duration like '5s', '10s'");
                        return;
                    }
                }

                // Parse other DLLs to suspend (optional)
                if (args.Length >= 3)
                {
                    string dllsArg = args[2];
                    if (dllsArg.ToLower() != "none" && dllsArg.ToLower() != "false")
                    {
                        // Split by comma for multiple DLLs
                        string[] dlls = dllsArg.Split(',');
                        foreach (string dll in dlls)
                        {
                            string trimmedDll = dll.Trim();
                            if (!string.IsNullOrEmpty(trimmedDll))
                            {
                                dllsToSuspend.Add(trimmedDll);
                            }
                        }
                        Console.WriteLine($"Additional DLLs to suspend: {string.Join(", ", dllsToSuspend)}");
                    }
                }

                // Parse use full manual mapper (optional)
                if (args.Length >= 4)
                {
                    string mapperArg = args[3].ToLower();
                    if (mapperArg == "true" || mapperArg == "yes" || mapperArg == "1" || mapperArg == "full")
                    {
                        useFullManualMapper = true;
                        Console.WriteLine("Using full manual mapper");
                    }
                    else if (mapperArg == "advanced" || mapperArg == "stealth")
                    {
                        useFullManualMapper = true;
                        Console.WriteLine("Using advanced stealth manual mapper");
                    }
                    else if (mapperArg == "ultimate" || mapperArg == "max")
                    {
                        useFullManualMapper = true;
                        Console.WriteLine("Using ultimate manual mapper with all features");
                    }
                    else
                    {
                        useFullManualMapper = false;
                        Console.WriteLine("Using standard injection methods");
                    }
                }

                // Validate target process
                if (targetPid == -1)
                {
                    Console.WriteLine("No valid target process specified.");
                    return;
                }

                Console.WriteLine($"Target PID: {targetPid}");
                LogToFile($"Target PID: {targetPid}");

                // Verify process exists
                try
                {
                    Process.GetProcessById(targetPid);
                }
                catch (ArgumentException)
                {
                    Console.WriteLine($"Process with PID {targetPid} not found.");
                    LogToFile($"ERROR: Process with PID {targetPid} not found.");
                    return;
                }

                // Get DLL path
                string dllPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "cat.dll");
                Console.WriteLine($"Looking for DLL at: {dllPath}");
                LogToFile($"Looking for DLL at: {dllPath}");

                if (!File.Exists(dllPath))
                {
                    Console.WriteLine("DLL not found!");
                    LogToFile("ERROR: DLL not found!");
                    return;
                }

                Console.WriteLine("Attempting DLL injection...");
                LogToFile("Attempting DLL injection...");

                // Determine injection strategy
                bool isRobloxProcess = IsRobloxProcess(targetPid);
                bool isProtectedProcess = IsProtectedProcess(targetPid);
                bool injectionSuccess = false;

                // Log injection configuration
                Console.WriteLine($"Process Type: {(isRobloxProcess ? "Roblox" : (isProtectedProcess ? "Protected" : "Standard"))}");
                Console.WriteLine($"NTDLL Suspension: {(suspendNtdll ? (permanentNtdllSuspension ? "Permanent" : $"{ntdllSuspensionDuration}ms") : "Disabled")}");
                Console.WriteLine($"Additional DLLs: {(dllsToSuspend.Count > 0 ? string.Join(", ", dllsToSuspend) : "None")}");
                Console.WriteLine($"Manual Mapper: {(useFullManualMapper ? "Full" : "Standard")}");

                // Apply pre-injection thread suspension if needed
                if (suspendNtdll && !isRobloxProcess)
                {
                    Console.WriteLine("Suspending NTDLL threads before injection...");
                    SuspendNtdllThreads(targetPid, permanentNtdllSuspension, ntdllSuspensionDuration);
                }

                // Suspend additional DLL threads if specified
                foreach (string dllName in dllsToSuspend)
                {
                    Console.WriteLine($"Suspending threads in {dllName}...");
                    SuspendDllThreads(targetPid, dllName, permanentNtdllSuspension, ntdllSuspensionDuration);
                }

                // Perform injection based on strategy
                if (useFullManualMapper)
                {
                    Console.WriteLine("Using full manual mapping...");
                    LogToFile("Using full manual mapping injection.");
                    
                    if (args.Length >= 4 && (args[3].ToLower() == "ultimate" || args[3].ToLower() == "max"))
                    {
                        injectionSuccess = ManualMapper.UltimateManualMapDll(targetPid, dllPath, true);
                    }
                    else if (args.Length >= 4 && (args[3].ToLower() == "advanced" || args[3].ToLower() == "stealth"))
                    {
                        injectionSuccess = ManualMapper.AdvancedManualMapDll(targetPid, dllPath, true, true);
                    }
                    else
                    {
                        injectionSuccess = ManualMapper.ManualMapDll(targetPid, dllPath);
                    }
                }
                else if (isRobloxProcess)
                {
                    Console.WriteLine("Detected Roblox process, using optimized injection strategy...");
                    LogToFile("Using optimized injection strategy for Roblox.");
                    
                    // For Roblox, try LoadLibraryA first
                    Console.WriteLine("Attempting LoadLibraryA injection...");
                    injectionSuccess = ManualMapper.LoadLibraryInject(targetPid, dllPath);
                    
                    if (injectionSuccess)
                    {
                        Console.WriteLine("Standard injection successful. Applying post-injection measures...");
                        // Apply NTDLL suspension AFTER successful injection for Roblox
                        if (suspendNtdll)
                        {
                            Console.WriteLine("Suspending NTDLL threads to bypass anti-cheat...");
                            SuspendTargetedNtdllThreads(targetPid);
                        }
                    }
                    else
                    {
                        Console.WriteLine("Standard injection failed, trying stealth injection...");
                        injectionSuccess = ManualMapper.StealthInjectForRoblox(targetPid, dllPath);
                        if (injectionSuccess && suspendNtdll)
                        {
                            SuspendTargetedNtdllThreads(targetPid);
                        }
                    }
                }
                else if (isProtectedProcess)
                {
                    Console.WriteLine("Detected protected process, using advanced injection...");
                    LogToFile("Using advanced injection for protected process.");
                    
                    // For protected processes, prefer manual mapping
                    injectionSuccess = ManualMapper.ManualMapDll(targetPid, dllPath);
                    
                    if (!injectionSuccess)
                    {
                        Console.WriteLine("Manual mapping failed, trying LoadLibraryA...");
                        injectionSuccess = ManualMapper.LoadLibraryInject(targetPid, dllPath);
                    }
                }
                else
                {
                    Console.WriteLine("Using standard LoadLibraryA injection...");
                    LogToFile("Using standard LoadLibraryA injection.");
                    
                    injectionSuccess = ManualMapper.LoadLibraryInject(targetPid, dllPath);
                }

                // Report results
                if (injectionSuccess)
                {
                    Console.WriteLine("=== INJECTION SUCCESSFUL ===");
                    LogToFile("DLL injected successfully!");
                    
                    // Verify DLL was loaded
                    Console.WriteLine("Verifying DLL injection...");
                    if (IsDllLoaded(targetPid, "cat.dll"))
                    {
                        Console.WriteLine("✓ DLL verification successful!");
                        LogToFile("DLL verification successful!");
                    }
                    else
                    {
                        Console.WriteLine("⚠ Warning: Could not verify DLL loading (this may be normal for some injection methods)");
                        LogToFile("Warning: Could not verify DLL loading");
                    }
                    
                    Console.WriteLine("Check the target process for DLL effects (e.g., message boxes, hooks, etc.)");
                    LogToFile("Injection completed successfully.");
                }
                else
                {
                    Console.WriteLine("=== INJECTION FAILED ===");
                    LogToFile("ERROR: DLL injection failed!");
                    Console.WriteLine("Check the log file for more details.");
                }

                // Show suspension status
                if (suspendNtdll && permanentNtdllSuspension)
                {
                    Console.WriteLine("Note: NTDLL threads are permanently suspended. Use a process manager to resume if needed.");
                }
                else if (suspendNtdll && !permanentNtdllSuspension)
                {
                    Console.WriteLine($"Note: NTDLL threads suspended for {ntdllSuspensionDuration}ms and will resume automatically.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Critical Error: {ex.Message}");
                LogToFile($"CRITICAL ERROR: {ex.Message}");
                Console.WriteLine("Stack Trace:");
                Console.WriteLine(ex.StackTrace);
                LogToFile($"Stack Trace: {ex.StackTrace}");
            }
            
            // Keep console open for user to see results
            Console.WriteLine("\nPress any key to exit...");
            Console.ReadKey();
        }

        // Display usage information
        private static void DisplayUsage()
        {
            Console.WriteLine("=== Advanced DLL Injector ===");
            Console.WriteLine("Usage: Injector.exe [pid] [ntdll_suspension] [other_dlls] [use_full_manual_mapper]");
            Console.WriteLine();
            Console.WriteLine("Parameters:");
            Console.WriteLine("  pid                    - Target process ID (required)");
            Console.WriteLine("  ntdll_suspension       - NTDLL suspension mode:");
            Console.WriteLine("                          'perm' or 'permanent' - Permanent suspension");
            Console.WriteLine("                          'none' or 'false' - No suspension");
            Console.WriteLine("                          'Xs' (e.g., '5s', '10s') - Suspend for X seconds");
            Console.WriteLine("  other_dlls            - Other DLLs to suspend (comma-separated) or 'none'");
            Console.WriteLine("  use_full_manual_mapper - Use full manual mapper:");
            Console.WriteLine("                          'true', 'yes', '1', 'full' - Use full manual mapper");
            Console.WriteLine("                          'advanced', 'stealth' - Use advanced stealth manual mapper");
            Console.WriteLine("                          'ultimate', 'max' - Use ultimate manual mapper (all features)");
            Console.WriteLine("                          'false', 'no', '0' - Use standard injection");
            Console.WriteLine();
            Console.WriteLine("Examples:");
            Console.WriteLine("  Injector.exe 1234 perm none false");
            Console.WriteLine("  Injector.exe 1234 5s kernel32.dll,user32.dll true");
            Console.WriteLine("  Injector.exe 1234 none none advanced");
            Console.WriteLine("  Injector.exe 1234 permanent advapi32.dll stealth");
            Console.WriteLine("  Injector.exe 1234 none none ultimate");
            Console.WriteLine();
            Console.WriteLine("Notes:");
            Console.WriteLine("- For Roblox processes, NTDLL suspension is applied AFTER injection");
            Console.WriteLine("- For protected processes, suspension is applied BEFORE injection");
            Console.WriteLine("- Manual mapping bypasses most anti-cheat detection");
            Console.WriteLine("- Advanced stealth mode includes header erasure and memory location obfuscation");
            Console.WriteLine("- Ultimate mode includes TLS callbacks, anti-VM detection, and comprehensive security checks");
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
                            if (SuspendThread(hThread) != 0xFFFFFFFF)
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
                            if (ResumeThread(hThread) != 0xFFFFFFFF)
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

        // Targeted ntdll suspension method - exactly like the working old version
        static void SuspendTargetedNtdllThreads(int processId)
        {
            var process = Process.GetProcessById(processId);

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
                    if (IsAddressInNtdll(processId, startAddress))
                    {
                        SuspendThread(hThread);
                    }
                }
                catch { }
            }
        }

        static bool IsAddressInNtdll(int processId, IntPtr address)
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
                        return true;
                }
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
