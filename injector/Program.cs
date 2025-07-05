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

            // Try multiple process names
            Process target = null;
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
                return;
            }

            try
            {
                Console.WriteLine($"Target PID: {target.Id}");
                Console.WriteLine("Attempting DLL injection...");
                InjectDll(target.Id, dllPath);
                Console.WriteLine("DLL injected successfully!");
                Console.WriteLine("Suspending threads in ntdll.dll...");
                SuspendThreadsInNtdll(target.Id);
                Console.WriteLine("Threads in ntdll.dll suspended.");
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

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll")]
        static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes,
            uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);

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
            const int PROCESS_ALL_ACCESS = 0x1F0FFF;
            const uint MEM_COMMIT = 0x1000;
            const uint PAGE_READWRITE = 0x04;

            Console.WriteLine($"Opening process {pid}...");
            IntPtr hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
            if (hProcess == IntPtr.Zero)
            {
                uint error = GetLastError();
                throw new Exception($"Cannot open process. Error code: {error}");
            }

            Console.WriteLine("Process opened successfully.");

            byte[] dllBytes = System.Text.Encoding.ASCII.GetBytes(dllPath + "\0");
            Console.WriteLine($"Allocating {dllBytes.Length} bytes in target process...");
            
            IntPtr allocAddress = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)dllBytes.Length, MEM_COMMIT, PAGE_READWRITE);
            if (allocAddress == IntPtr.Zero)
            {
                uint error = GetLastError();
                throw new Exception($"Memory allocation failed. Error code: {error}");
            }

            Console.WriteLine($"Memory allocated at: 0x{allocAddress:X}");

            IntPtr bytesWritten;
            bool writeResult = WriteProcessMemory(hProcess, allocAddress, dllBytes, (uint)dllBytes.Length, out bytesWritten);
            if (!writeResult)
            {
                uint error = GetLastError();
                throw new Exception($"WriteProcessMemory failed. Error code: {error}");
            }

            Console.WriteLine($"DLL path written to target process.");

            // Get LoadLibraryA address
            IntPtr loadLibraryAddr = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
            if (loadLibraryAddr == IntPtr.Zero)
                throw new Exception("LoadLibraryA address not found");

            Console.WriteLine($"LoadLibraryA address: 0x{loadLibraryAddr:X}");

            // Create remote thread
            IntPtr threadId = IntPtr.Zero;
            IntPtr remoteThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, loadLibraryAddr, allocAddress, 0, out threadId);
            if (remoteThread == IntPtr.Zero)
            {
                uint error = GetLastError();
                throw new Exception($"CreateRemoteThread failed. Error code: {error}");
            }

            Console.WriteLine($"Remote thread created successfully. Thread ID: {threadId}");
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
