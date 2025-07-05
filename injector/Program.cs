using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;

namespace Injector
{
    class Program
    {
        // Entry point
        static void Main(string[] args)
        {
            // Get absolute path to cat.dll
            string dllPath = Path.GetFullPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "cat.dll"));
            Console.WriteLine($"Looking for DLL at: {dllPath}");
            
            if (!File.Exists(dllPath))
            {
                Console.WriteLine("cat.dll not found in current directory.");
                Console.WriteLine("Current directory: " + AppDomain.CurrentDomain.BaseDirectory);
                return;
            }

            Console.WriteLine("cat.dll found successfully!");

            Process target = null;
            
            // If PID is provided as argument, use it for testing
            if (args.Length > 0 && int.TryParse(args[0], out int testPid))
            {
                try
                {
                    target = Process.GetProcessById(testPid);
                    Console.WriteLine($"Using provided PID: {testPid} ({target.ProcessName})");
                }
                catch (ArgumentException)
                {
                    Console.WriteLine($"Process with PID {testPid} not found.");
                    return;
                }
            }
            else
            {
                // Try multiple process names
                string[] processNames = { "RobloxPlayerBeta", "Roblox", "Windows10Universal" };
                
                foreach (string processName in processNames)
                {
                    target = Process.GetProcessesByName(processName).FirstOrDefault();
                    if (target != null)
                    {
                        Console.WriteLine($"Found target process: {processName} (PID: {target.Id})");
                        break;
                    }
                }

                if (target == null)
                {
                    Console.WriteLine("No Roblox process found. Make sure Roblox is running.");
                    Console.WriteLine("Available processes:");
                    foreach (Process p in Process.GetProcesses())
                    {
                        if (p.ProcessName.ToLower().Contains("roblox"))
                        {
                            Console.WriteLine($"  - {p.ProcessName} (PID: {p.Id})");
                        }
                    }
                    Console.WriteLine("\nUsage: Injector.exe [PID] to inject into a specific process");
                    return;
                }
            }

            try
            {
                Console.WriteLine($"Target PID: {target.Id}");
                Console.WriteLine($"Target Process: {target.ProcessName}");
                Console.WriteLine($"Target Architecture: {(Environment.Is64BitProcess ? "64-bit" : "32-bit")}");
                Console.WriteLine("Suspending threads in ntdll.dll...");
                SuspendThreadsInNtdll(target.Id);
                Console.WriteLine("Threads in ntdll.dll suspended.");
                Console.WriteLine("Attempting DLL injection...");
                InjectDll(target.Id, dllPath);
                Console.WriteLine("DLL injected successfully!");
                Console.WriteLine("Check for a message box from the target process.");
            }
            catch (Exception ex)
            {
                Console.WriteLine("Injection failed: " + ex.Message);
                Console.WriteLine("Stack trace: " + ex.StackTrace);
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

        [Flags]
        public enum ThreadAccess : int
        {
            SUSPEND_RESUME = 0x0002,
            QUERY_INFORMATION = 0x0040
        }

        static void InjectDll(int pid, string dllPath)
        {
            Console.WriteLine($"Manual mapping DLL into process {pid}...");
            
            bool success = ManualMapper.ManualMapDll(pid, dllPath);
            
            if (success)
            {
                Console.WriteLine("Manual mapping completed successfully!");
                
                // Verify DLL was loaded by checking process modules
                Console.WriteLine("Verifying DLL was loaded...");
                try
                {
                    var targetProcess = Process.GetProcessById(pid);
                    bool dllFound = false;
                    foreach (ProcessModule module in targetProcess.Modules)
                    {
                        if (module.ModuleName.ToLower().Contains("cat.dll"))
                        {
                            Console.WriteLine($"DLL found in process: {module.ModuleName} at 0x{module.BaseAddress:X}");
                            dllFound = true;
                            break;
                        }
                    }
                    if (!dllFound)
                    {
                        Console.WriteLine("Note: cat.dll may not appear in module list with manual mapping (this is normal)");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Warning: Could not verify DLL loading: {ex.Message}");
                }
            }
            else
            {
                throw new Exception("Manual mapping failed");
            }
        }

        static void SuspendThreadsInNtdll(int pid)
        {
            var process = Process.GetProcessById(pid);

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
                    if (IsAddressInNtdll(pid, startAddress))
                    {
                        SuspendThread(hThread);
                    }
                }
                catch { }
            }
        }

        static bool IsAddressInNtdll(int pid, IntPtr address)
        {
            var process = Process.GetProcessById(pid);
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
    }
}
