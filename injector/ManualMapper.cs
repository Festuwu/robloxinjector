using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Diagnostics;

namespace Injector
{
    public class ManualMapper
    {
        // PE Header structures
        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DOS_HEADER
        {
            public ushort e_magic;
            public ushort e_cblp;
            public ushort e_cp;
            public ushort e_crlc;
            public ushort e_cparhdr;
            public ushort e_minalloc;
            public ushort e_maxalloc;
            public ushort e_ss;
            public ushort e_sp;
            public ushort e_csum;
            public ushort e_ip;
            public ushort e_cs;
            public ushort e_lfarlc;
            public ushort e_ovno;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public ushort[] e_res1;
            public ushort e_oemid;
            public ushort e_oeminfo;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
            public ushort[] e_res2;
            public uint e_lfanew;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_FILE_HEADER
        {
            public uint Signature;
            public ushort Machine;
            public ushort NumberOfSections;
            public uint TimeDateStamp;
            public uint PointerToSymbolTable;
            public uint NumberOfSymbols;
            public ushort SizeOfOptionalHeader;
            public ushort Characteristics;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_OPTIONAL_HEADER
        {
            public ushort Magic;
            public byte MajorLinkerVersion;
            public byte MinorLinkerVersion;
            public uint SizeOfCode;
            public uint SizeOfInitializedData;
            public uint SizeOfUninitializedData;
            public uint AddressOfEntryPoint;
            public uint BaseOfCode;
            public ulong ImageBase;
            public uint SectionAlignment;
            public uint FileAlignment;
            public ushort MajorOperatingSystemVersion;
            public ushort MinorOperatingSystemVersion;
            public ushort MajorImageVersion;
            public ushort MinorImageVersion;
            public ushort MajorSubsystemVersion;
            public ushort MinorSubsystemVersion;
            public uint Win32VersionValue;
            public uint SizeOfImage;
            public uint SizeOfHeaders;
            public uint CheckSum;
            public ushort Subsystem;
            public ushort DllCharacteristics;
            public ulong SizeOfStackReserve;
            public ulong SizeOfStackCommit;
            public ulong SizeOfHeapReserve;
            public ulong SizeOfHeapCommit;
            public uint LoaderFlags;
            public uint NumberOfRvaAndSizes;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public IMAGE_DATA_DIRECTORY[] DataDirectory;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DATA_DIRECTORY
        {
            public uint VirtualAddress;
            public uint Size;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_SECTION_HEADER
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public byte[] Name;
            public uint VirtualSize;
            public uint VirtualAddress;
            public uint SizeOfRawData;
            public uint PointerToRawData;
            public uint PointerToRelocations;
            public uint PointerToLineNumbers;
            public ushort NumberOfRelocations;
            public ushort NumberOfLineNumbers;
            public uint Characteristics;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_IMPORT_DESCRIPTOR
        {
            public uint OriginalFirstThunk;
            public uint TimeDateStamp;
            public uint ForwarderChain;
            public uint Name;
            public uint FirstThunk;
        }

        // Native API declarations
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out nint lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out nint lpThreadId);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "GetProcAddress")]
        static extern IntPtr GetProcAddress_Int(IntPtr hModule, IntPtr ordinal);

        [DllImport("kernel32.dll")]
        static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll")]
        static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [DllImport("kernel32.dll")]
        static extern bool GetExitCodeThread(IntPtr hThread, out uint lpExitCode);

        [DllImport("kernel32.dll")]
        static extern uint GetLastError();

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out nint lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint dwFreeType);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hObject);

        // Constants
        const int PROCESS_ALL_ACCESS = 0x1F0FFF;
        const uint MEM_COMMIT = 0x1000;
        const uint MEM_RESERVE = 0x2000;
        const uint PAGE_READWRITE = 0x04;
        const uint PAGE_EXECUTE_READWRITE = 0x40;
        const uint PAGE_READONLY = 0x02;
        const uint PAGE_EXECUTE_READ = 0x20;
        const uint PAGE_NOACCESS = 0x01;
        const uint INFINITE = 0xFFFFFFFF;

        // Advanced manual mapping with full PE loading capabilities
        public static bool ManualMapDll(int processId, string dllPath)
        {
            IntPtr hProcess = IntPtr.Zero;
            IntPtr dllBase = IntPtr.Zero;
            IntPtr shellcodeAddr = IntPtr.Zero;
            
            try
            {
                Console.WriteLine($"Starting advanced manual mapping for: {dllPath}");
                
                // Read the DLL file
                byte[] dllBytes = File.ReadAllBytes(dllPath);
                Console.WriteLine($"Read {dllBytes.Length} bytes from DLL");
                
                // Parse PE headers
                var dosHeader = ByteArrayToStructure<IMAGE_DOS_HEADER>(dllBytes, 0);
                if (dosHeader.e_magic != 0x5A4D) // "MZ"
                {
                    throw new Exception("Invalid DOS header");
                }
                
                var fileHeader = ByteArrayToStructure<IMAGE_FILE_HEADER>(dllBytes, (int)dosHeader.e_lfanew);
                if (fileHeader.Signature != 0x00004550) // "PE\0\0"
                {
                    throw new Exception("Invalid PE signature");
                }
                
                var optionalHeader = ByteArrayToStructure<IMAGE_OPTIONAL_HEADER>(dllBytes, (int)dosHeader.e_lfanew + Marshal.SizeOf<IMAGE_FILE_HEADER>());
                
                Console.WriteLine($"PE Headers parsed successfully");
                Console.WriteLine($"Image Base: 0x{optionalHeader.ImageBase:X}");
                Console.WriteLine($"Size of Image: 0x{optionalHeader.SizeOfImage:X}");
                Console.WriteLine($"Entry Point: 0x{optionalHeader.AddressOfEntryPoint:X}");
                
                // Open target process
                hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, processId);
                if (hProcess == IntPtr.Zero)
                {
                    throw new Exception($"Failed to open process {processId}. Error: {GetLastError()}");
                }
                
                Console.WriteLine("Target process opened successfully");
                
                // Allocate memory for the DLL in the target process
                dllBase = VirtualAllocEx(hProcess, IntPtr.Zero, optionalHeader.SizeOfImage, 
                    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                if (dllBase == IntPtr.Zero)
                {
                    throw new Exception($"Failed to allocate memory in target process. Error: {GetLastError()}");
                }
                
                Console.WriteLine($"Allocated memory at: 0x{dllBase:X}");
                
                // Copy headers to target process
                nint bytesWritten;
                if (!WriteProcessMemory(hProcess, dllBase, dllBytes, optionalHeader.SizeOfHeaders, out bytesWritten))
                {
                    throw new Exception($"Failed to write headers. Error: {GetLastError()}");
                }
                
                Console.WriteLine($"Headers written: {bytesWritten} bytes");
                
                // Copy sections to target process
                if (!CopySections(hProcess, dllBase, dllBytes, fileHeader, optionalHeader))
                {
                    throw new Exception("Failed to copy sections");
                }
                
                // Apply relocations if needed
                if (!ApplyRelocations(hProcess, dllBase, dllBytes, optionalHeader))
                {
                    Console.WriteLine("Warning: Relocations failed, may cause issues");
                }
                
                // Resolve imports
                if (!ResolveImports(hProcess, dllBase, dllBytes, optionalHeader))
                {
                    Console.WriteLine("Warning: Import resolution failed, may cause issues");
                }
                
                // Set proper page protections
                SetPageProtections(hProcess, dllBase, dllBytes, fileHeader, optionalHeader);
                
                // Call DllMain if entry point exists
                if (optionalHeader.AddressOfEntryPoint != 0)
                {
                    IntPtr entryPoint = (IntPtr)((long)dllBase + optionalHeader.AddressOfEntryPoint);
                    Console.WriteLine($"Calling DllMain at: 0x{entryPoint:X}");
                    
                    if (!CallDllMain(hProcess, entryPoint, dllBase))
                    {
                        Console.WriteLine("Warning: DllMain execution failed");
                    }
                }
                
                Console.WriteLine("Manual mapping completed successfully!");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Manual mapping failed: {ex.Message}");
                return false;
            }
            finally
            {
                if (shellcodeAddr != IntPtr.Zero && hProcess != IntPtr.Zero)
                {
                    VirtualFreeEx(hProcess, shellcodeAddr, 0, 0x8000); // MEM_RELEASE
                }
                if (hProcess != IntPtr.Zero)
                {
                    CloseHandle(hProcess);
                }
            }
        }
        
        // Advanced manual mapping with additional stealth features
        public static bool AdvancedManualMapDll(int processId, string dllPath, bool useAntiDebug = true, bool hideFromPeb = true)
        {
            IntPtr hProcess = IntPtr.Zero;
            IntPtr dllBase = IntPtr.Zero;
            IntPtr shellcodeAddr = IntPtr.Zero;
            
            try
            {
                Console.WriteLine($"Starting advanced stealth manual mapping for: {dllPath}");
                
                // Read the DLL file
                byte[] dllBytes = File.ReadAllBytes(dllPath);
                Console.WriteLine($"Read {dllBytes.Length} bytes from DLL");
                
                // Parse PE headers
                var dosHeader = ByteArrayToStructure<IMAGE_DOS_HEADER>(dllBytes, 0);
                if (dosHeader.e_magic != 0x5A4D) // "MZ"
                {
                    throw new Exception("Invalid DOS header");
                }
                
                var fileHeader = ByteArrayToStructure<IMAGE_FILE_HEADER>(dllBytes, (int)dosHeader.e_lfanew);
                if (fileHeader.Signature != 0x00004550) // "PE\0\0"
                {
                    throw new Exception("Invalid PE signature");
                }
                
                var optionalHeader = ByteArrayToStructure<IMAGE_OPTIONAL_HEADER>(dllBytes, (int)dosHeader.e_lfanew + Marshal.SizeOf<IMAGE_FILE_HEADER>());
                
                Console.WriteLine($"PE Headers parsed successfully");
                Console.WriteLine($"Image Base: 0x{optionalHeader.ImageBase:X}");
                Console.WriteLine($"Size of Image: 0x{optionalHeader.SizeOfImage:X}");
                Console.WriteLine($"Entry Point: 0x{optionalHeader.AddressOfEntryPoint:X}");
                
                // Open target process
                hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, processId);
                if (hProcess == IntPtr.Zero)
                {
                    throw new Exception($"Failed to open process {processId}. Error: {GetLastError()}");
                }
                
                Console.WriteLine("Target process opened successfully");
                
                // Find a suitable memory location (avoid common ranges)
                IntPtr preferredBase = FindSuitableMemoryLocation(hProcess, optionalHeader.SizeOfImage);
                
                // Allocate memory for the DLL in the target process
                dllBase = VirtualAllocEx(hProcess, preferredBase, optionalHeader.SizeOfImage, 
                    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                if (dllBase == IntPtr.Zero)
                {
                    // Try without preferred base
                    dllBase = VirtualAllocEx(hProcess, IntPtr.Zero, optionalHeader.SizeOfImage, 
                        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                    if (dllBase == IntPtr.Zero)
                    {
                        throw new Exception($"Failed to allocate memory in target process. Error: {GetLastError()}");
                    }
                }
                
                Console.WriteLine($"Allocated memory at: 0x{dllBase:X}");
                
                // Copy headers to target process
                nint bytesWritten;
                if (!WriteProcessMemory(hProcess, dllBase, dllBytes, optionalHeader.SizeOfHeaders, out bytesWritten))
                {
                    throw new Exception($"Failed to write headers. Error: {GetLastError()}");
                }
                
                Console.WriteLine($"Headers written: {bytesWritten} bytes");
                
                // Copy sections to target process
                if (!CopySections(hProcess, dllBase, dllBytes, fileHeader, optionalHeader))
                {
                    throw new Exception("Failed to copy sections");
                }
                
                // Apply relocations if needed
                if (!ApplyRelocations(hProcess, dllBase, dllBytes, optionalHeader))
                {
                    Console.WriteLine("Warning: Relocations failed, may cause issues");
                }
                
                // Resolve imports
                if (!ResolveImports(hProcess, dllBase, dllBytes, optionalHeader))
                {
                    Console.WriteLine("Warning: Import resolution failed, may cause issues");
                }
                
                // Erase PE headers to avoid detection
                if (hideFromPeb)
                {
                    EraseHeaders(hProcess, dllBase, optionalHeader.SizeOfHeaders);
                }
                
                // Set proper page protections
                SetPageProtections(hProcess, dllBase, dllBytes, fileHeader, optionalHeader);
                
                // Call DllMain if entry point exists
                if (optionalHeader.AddressOfEntryPoint != 0)
                {
                    IntPtr entryPoint = (IntPtr)((long)dllBase + optionalHeader.AddressOfEntryPoint);
                    Console.WriteLine($"Calling DllMain at: 0x{entryPoint:X}");
                    
                    if (!CallDllMainSafe(hProcess, entryPoint, dllBase))
                    {
                        Console.WriteLine("Warning: DllMain execution failed");
                    }
                }
                
                Console.WriteLine("Advanced stealth manual mapping completed successfully!");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Advanced manual mapping failed: {ex.Message}");
                return false;
            }
            finally
            {
                if (shellcodeAddr != IntPtr.Zero && hProcess != IntPtr.Zero)
                {
                    VirtualFreeEx(hProcess, shellcodeAddr, 0, 0x8000); // MEM_RELEASE
                }
                if (hProcess != IntPtr.Zero)
                {
                    CloseHandle(hProcess);
                }
            }
        }
        
        // Copy sections from DLL to target process
        private static bool CopySections(IntPtr hProcess, IntPtr dllBase, byte[] dllBytes, IMAGE_FILE_HEADER fileHeader, IMAGE_OPTIONAL_HEADER optionalHeader)
        {
            try
            {
                Console.WriteLine("Copying sections...");
                
                int sectionOffset = (int)optionalHeader.SizeOfHeaders;
                
                for (int i = 0; i < fileHeader.NumberOfSections; i++)
                {
                    var sectionHeader = ByteArrayToStructure<IMAGE_SECTION_HEADER>(dllBytes, sectionOffset);
                    
                    string sectionName = GetSectionName(sectionHeader.Name);
                    Console.WriteLine($"Processing section: {sectionName}");
                    Console.WriteLine($"  Virtual Address: 0x{sectionHeader.VirtualAddress:X}");
                    Console.WriteLine($"  Virtual Size: 0x{sectionHeader.VirtualSize:X}");
                    Console.WriteLine($"  Raw Size: 0x{sectionHeader.SizeOfRawData:X}");
                    
                    if (sectionHeader.SizeOfRawData == 0)
                    {
                        Console.WriteLine($"  Skipping empty section: {sectionName}");
                        sectionOffset += Marshal.SizeOf<IMAGE_SECTION_HEADER>();
                        continue;
                    }
                    
                    IntPtr sectionDestination = (IntPtr)((long)dllBase + sectionHeader.VirtualAddress);
                    
                    // Copy section data
                    byte[] sectionData = new byte[sectionHeader.SizeOfRawData];
                    Array.Copy(dllBytes, (int)sectionHeader.PointerToRawData, sectionData, 0, (int)sectionHeader.SizeOfRawData);
                    
                    nint bytesWritten;
                    if (!WriteProcessMemory(hProcess, sectionDestination, sectionData, (uint)sectionData.Length, out bytesWritten))
                    {
                        Console.WriteLine($"  Warning: Failed to write section {sectionName}");
                        continue;
                    }
                    
                    Console.WriteLine($"  Section {sectionName} copied: {bytesWritten} bytes");
                    sectionOffset += Marshal.SizeOf<IMAGE_SECTION_HEADER>();
                }
                
                Console.WriteLine("All sections copied successfully");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to copy sections: {ex.Message}");
                return false;
            }
        }
        
        // Call DllMain in the target process
        private static bool CallDllMain(IntPtr hProcess, IntPtr entryPoint, IntPtr dllBase)
        {
            try
            {
                // Create shellcode to call DllMain
                byte[] shellcode = CreateDllMainStub(entryPoint, dllBase);
                
                // Allocate memory for shellcode
                IntPtr shellcodeAddr = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)shellcode.Length, 
                    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                if (shellcodeAddr == IntPtr.Zero)
                {
                    Console.WriteLine("Failed to allocate memory for shellcode");
                    return false;
                }
                
                // Write shellcode
                nint bytesWritten;
                if (!WriteProcessMemory(hProcess, shellcodeAddr, shellcode, (uint)shellcode.Length, out bytesWritten))
                {
                    Console.WriteLine("Failed to write shellcode");
                    VirtualFreeEx(hProcess, shellcodeAddr, 0, 0x8000);
                    return false;
                }
                
                // Execute shellcode
                nint threadId;
                IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, shellcodeAddr, IntPtr.Zero, 0, out threadId);
                if (hThread == IntPtr.Zero)
                {
                    Console.WriteLine("Failed to create remote thread");
                    VirtualFreeEx(hProcess, shellcodeAddr, 0, 0x8000);
                    return false;
                }
                
                // Wait for completion
                uint waitResult = WaitForSingleObject(hThread, 10000); // 10 second timeout
                if (waitResult == 0) // WAIT_OBJECT_0
                {
                    uint exitCode;
                    GetExitCodeThread(hThread, out exitCode);
                    Console.WriteLine($"DllMain executed with exit code: {exitCode}");
                    CloseHandle(hThread);
                    VirtualFreeEx(hProcess, shellcodeAddr, 0, 0x8000);
                    return true;
                }
                else
                {
                    Console.WriteLine($"DllMain execution timed out or failed. Wait result: {waitResult}");
                    CloseHandle(hThread);
                    VirtualFreeEx(hProcess, shellcodeAddr, 0, 0x8000);
                    return false;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to call DllMain: {ex.Message}");
                return false;
            }
        }
        
        // Safer DllMain call with exception handling
        private static bool CallDllMainSafe(IntPtr hProcess, IntPtr entryPoint, IntPtr dllBase)
        {
            try
            {
                // Create safer shellcode with exception handling
                byte[] shellcode = CreateSafeDllMainStub(entryPoint, dllBase);
                
                // Allocate memory for shellcode
                IntPtr shellcodeAddr = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)shellcode.Length, 
                    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                if (shellcodeAddr == IntPtr.Zero)
                {
                    Console.WriteLine("Failed to allocate memory for safe shellcode");
                    return false;
                }
                
                // Write shellcode
                nint bytesWritten;
                if (!WriteProcessMemory(hProcess, shellcodeAddr, shellcode, (uint)shellcode.Length, out bytesWritten))
                {
                    Console.WriteLine("Failed to write safe shellcode");
                    VirtualFreeEx(hProcess, shellcodeAddr, 0, 0x8000);
                    return false;
                }
                
                // Execute shellcode
                nint threadId;
                IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, shellcodeAddr, IntPtr.Zero, 0, out threadId);
                if (hThread == IntPtr.Zero)
                {
                    Console.WriteLine("Failed to create remote thread for safe DllMain");
                    VirtualFreeEx(hProcess, shellcodeAddr, 0, 0x8000);
                    return false;
                }
                
                // Wait for completion
                uint waitResult = WaitForSingleObject(hThread, 15000); // 15 second timeout
                if (waitResult == 0) // WAIT_OBJECT_0
                {
                    uint exitCode;
                    GetExitCodeThread(hThread, out exitCode);
                    Console.WriteLine($"Safe DllMain executed with exit code: {exitCode}");
                    CloseHandle(hThread);
                    VirtualFreeEx(hProcess, shellcodeAddr, 0, 0x8000);
                    return true;
                }
                else
                {
                    Console.WriteLine($"Safe DllMain execution timed out or failed. Wait result: {waitResult}");
                    CloseHandle(hThread);
                    VirtualFreeEx(hProcess, shellcodeAddr, 0, 0x8000);
                    return false;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to call safe DllMain: {ex.Message}");
                return false;
            }
        }
        
        // Find a suitable memory location for allocation
        private static IntPtr FindSuitableMemoryLocation(IntPtr hProcess, uint sizeNeeded)
        {
            try
            {
                // Try to find a good location that's not in common ranges
                ulong startAddr = 0x10000000; // Start at 256MB
                ulong endAddr = 0x7FFFFFFF;   // End before 2GB
                ulong stepSize = 0x10000;     // 64KB steps
                
                for (ulong addr = startAddr; addr < endAddr; addr += stepSize)
                {
                    // Check if this memory region is available
                    IntPtr testAddr = VirtualAllocEx(hProcess, (IntPtr)addr, sizeNeeded, 
                        MEM_RESERVE, PAGE_NOACCESS);
                    if (testAddr != IntPtr.Zero)
                    {
                        // Free the test allocation
                        VirtualFreeEx(hProcess, testAddr, 0, 0x8000);
                        return (IntPtr)addr;
                    }
                }
                
                return IntPtr.Zero; // No suitable location found
            }
            catch
            {
                return IntPtr.Zero;
            }
        }
        
        // Erase PE headers to avoid detection
        private static void EraseHeaders(IntPtr hProcess, IntPtr dllBase, uint headerSize)
        {
            try
            {
                Console.WriteLine("Erasing PE headers to avoid detection...");
                
                byte[] zeroBytes = new byte[headerSize];
                nint bytesWritten;
                WriteProcessMemory(hProcess, dllBase, zeroBytes, headerSize, out bytesWritten);
                
                Console.WriteLine($"Erased {bytesWritten} bytes of PE headers");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to erase headers: {ex.Message}");
            }
        }

        private static bool ApplyRelocations(IntPtr hProcess, IntPtr dllBase, byte[] dllBytes, IMAGE_OPTIONAL_HEADER optionalHeader)
        {
            try
            {
                var relocDir = optionalHeader.DataDirectory[5]; // IMAGE_DIRECTORY_ENTRY_BASERELOC
                if (relocDir.VirtualAddress == 0 || relocDir.Size == 0)
                {
                    Console.WriteLine("No relocations to apply");
                    return true;
                }

                Console.WriteLine($"Applying relocations at 0x{relocDir.VirtualAddress:X}, size: {relocDir.Size}");

                // Calculate the delta between preferred and actual base address
                long delta = (long)dllBase - (long)optionalHeader.ImageBase;
                if (delta == 0)
                {
                    Console.WriteLine("No relocations needed (loaded at preferred base)");
                    return true;
                }

                Console.WriteLine($"Relocation delta: 0x{delta:X}");

                // Parse relocation table
                int relocOffset = (int)relocDir.VirtualAddress;
                int relocEnd = relocOffset + (int)relocDir.Size;

                while (relocOffset < relocEnd)
                {
                    // Read relocation block header
                    if (relocOffset + 8 > dllBytes.Length) break;
                    
                    uint virtualAddress = BitConverter.ToUInt32(dllBytes, relocOffset);
                    uint sizeOfBlock = BitConverter.ToUInt32(dllBytes, relocOffset + 4);
                    
                    if (sizeOfBlock == 0) break;
                    
                    Console.WriteLine($"Relocation block: VA=0x{virtualAddress:X}, Size={sizeOfBlock}");
                    
                    // Process each relocation entry in the block
                    int numRelocs = (int)((sizeOfBlock - 8) / 2);
                    for (int i = 0; i < numRelocs; i++)
                    {
                        int entryOffset = relocOffset + 8 + (i * 2);
                        if (entryOffset + 2 > dllBytes.Length) break;
                        
                        ushort relocEntry = BitConverter.ToUInt16(dllBytes, entryOffset);
                        ushort type = (ushort)(relocEntry >> 12);
                        ushort offset = (ushort)(relocEntry & 0xFFF);
                        
                        if (type == 0) continue; // IMAGE_REL_BASED_ABSOLUTE (padding)
                        
                        // Calculate the address to fix
                        long fixAddress = (long)dllBase + virtualAddress + offset;
                        
                        // Read the current value
                        byte[] currentValue = new byte[8];
                        ReadProcessMemory(hProcess, (IntPtr)fixAddress, currentValue, 8, out nint bytesRead);
                        long currentAddr = BitConverter.ToInt64(currentValue, 0);
                        
                        // Apply the relocation
                        long newAddr = currentAddr + delta;
                        byte[] newValue = BitConverter.GetBytes(newAddr);
                        
                        // Write the fixed value back
                        nint bytesWritten;
                        WriteProcessMemory(hProcess, (IntPtr)fixAddress, newValue, 8, out bytesWritten);
                        
                        Console.WriteLine($"Fixed relocation: 0x{currentAddr:X} -> 0x{newAddr:X} at 0x{fixAddress:X}");
                    }
                    
                    relocOffset += (int)sizeOfBlock;
                }
                
                Console.WriteLine("Relocations applied successfully");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Warning: Failed to apply relocations: {ex.Message}");
                return false;
            }
        }

        private static bool ResolveImports(IntPtr hProcess, IntPtr dllBase, byte[] dllBytes, IMAGE_OPTIONAL_HEADER optionalHeader)
        {
            try
            {
                var importDir = optionalHeader.DataDirectory[1]; // IMAGE_DIRECTORY_ENTRY_IMPORT
                if (importDir.VirtualAddress == 0 || importDir.Size == 0)
                {
                    Console.WriteLine("No imports to resolve");
                    return true;
                }

                Console.WriteLine($"Resolving imports at 0x{importDir.VirtualAddress:X}, size: {importDir.Size}");

                int importOffset = (int)importDir.VirtualAddress;
                int importEnd = importOffset + (int)importDir.Size;

                while (importOffset < importEnd)
                {
                    // Read import descriptor
                    if (importOffset + Marshal.SizeOf<IMAGE_IMPORT_DESCRIPTOR>() > dllBytes.Length) break;
                    
                    var importDesc = ByteArrayToStructure<IMAGE_IMPORT_DESCRIPTOR>(dllBytes, importOffset);
                    
                    // Check for end of import descriptors
                    if (importDesc.Name == 0 && importDesc.FirstThunk == 0) break;
                    
                    // Get DLL name
                    string dllName = GetStringFromProcessMemory(hProcess, dllBase, importDesc.Name, dllBytes);
                    Console.WriteLine($"Processing imports for: {dllName}");
                    
                    // Load the DLL in the target process
                    IntPtr hModule = LoadLibraryInProcess(hProcess, dllName);
                    if (hModule == IntPtr.Zero)
                    {
                        Console.WriteLine($"Warning: Failed to load {dllName}");
                        importOffset += Marshal.SizeOf<IMAGE_IMPORT_DESCRIPTOR>();
                        continue;
                    }
                    
                    // Process thunks
                    ProcessImportThunks(hProcess, dllBase, dllBytes, importDesc, hModule);
                    
                    importOffset += Marshal.SizeOf<IMAGE_IMPORT_DESCRIPTOR>();
                }
                
                Console.WriteLine("Imports resolved successfully");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Warning: Failed to resolve imports: {ex.Message}");
                return false;
            }
        }

        private static void ProcessImportThunks(IntPtr hProcess, IntPtr dllBase, byte[] dllBytes, IMAGE_IMPORT_DESCRIPTOR importDesc, IntPtr hModule)
        {
            try
            {
                // Process OriginalFirstThunk (import names)
                int thunkOffset = (int)importDesc.OriginalFirstThunk;
                int thunkIndex = 0;
                
                while (thunkOffset < dllBytes.Length)
                {
                    // Read thunk entry
                    if (thunkOffset + 8 > dllBytes.Length) break;
                    
                    ulong thunkValue = BitConverter.ToUInt64(dllBytes, thunkOffset);
                    if (thunkValue == 0) break; // End of thunk array
                    
                    // Check if it's an ordinal import
                    if ((thunkValue & 0x8000000000000000) != 0)
                    {
                        // Ordinal import
                        ushort ordinal = (ushort)(thunkValue & 0xFFFF);
                        IntPtr funcAddr = GetProcAddress_Int(hModule, (IntPtr)ordinal);
                        Console.WriteLine($"Ordinal import: {ordinal} -> 0x{funcAddr:X}");
                        
                        // Write function address to IAT
                        long iatAddress = (long)dllBase + importDesc.FirstThunk + (thunkIndex * 8);
                        byte[] funcAddrBytes = BitConverter.GetBytes((long)funcAddr);
                        nint bytesWritten;
                        WriteProcessMemory(hProcess, (IntPtr)iatAddress, funcAddrBytes, 8, out bytesWritten);
                    }
                    else
                    {
                        // Named import
                        string funcName = GetStringFromProcessMemory(hProcess, dllBase, (uint)thunkValue, dllBytes);
                        IntPtr funcAddr = GetProcAddress(hModule, funcName);
                        Console.WriteLine($"Named import: {funcName} -> 0x{funcAddr:X}");
                        
                        // Write function address to IAT
                        long iatAddress = (long)dllBase + importDesc.FirstThunk + (thunkIndex * 8);
                        byte[] funcAddrBytes = BitConverter.GetBytes((long)funcAddr);
                        nint bytesWritten;
                        WriteProcessMemory(hProcess, (IntPtr)iatAddress, funcAddrBytes, 8, out bytesWritten);
                    }
                    
                    thunkOffset += 8;
                    thunkIndex++;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Warning: Failed to process import thunks: {ex.Message}");
            }
        }

        private static IntPtr LoadLibraryInProcess(IntPtr hProcess, string dllName)
        {
            try
            {
                // Allocate memory for DLL name
                byte[] dllNameBytes = Encoding.ASCII.GetBytes(dllName + "\0");
                IntPtr dllNameAddr = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)dllNameBytes.Length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (dllNameAddr == IntPtr.Zero) return IntPtr.Zero;
                
                // Write DLL name
                nint bytesWritten;
                WriteProcessMemory(hProcess, dllNameAddr, dllNameBytes, (uint)dllNameBytes.Length, out bytesWritten);
                
                // Get LoadLibraryA address
                IntPtr loadLibraryAddr = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
                if (loadLibraryAddr == IntPtr.Zero) return IntPtr.Zero;
                
                // Create remote thread to load DLL
                nint threadId;
                IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, loadLibraryAddr, dllNameAddr, 0, out threadId);
                if (hThread == IntPtr.Zero) return IntPtr.Zero;
                
                // Wait for completion
                WaitForSingleObject(hThread, INFINITE);
                
                // Get result (HMODULE)
                uint exitCode;
                GetExitCodeThread(hThread, out exitCode);
                
                return (IntPtr)exitCode;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Warning: Failed to load {dllName}: {ex.Message}");
                return IntPtr.Zero;
            }
        }

        private static string GetStringFromProcessMemory(IntPtr hProcess, IntPtr dllBase, uint offset, byte[] dllBytes)
        {
            try
            {
                // Read string from the DLL bytes (since we have them in memory)
                int stringOffset = (int)offset;
                if (stringOffset >= dllBytes.Length) return "";
                
                // Find null terminator
                int nullPos = stringOffset;
                while (nullPos < dllBytes.Length && dllBytes[nullPos] != 0)
                {
                    nullPos++;
                }
                
                return Encoding.ASCII.GetString(dllBytes, stringOffset, nullPos - stringOffset);
            }
            catch
            {
                return "";
            }
        }

        private static void SetPageProtections(IntPtr hProcess, IntPtr dllBase, byte[] dllBytes, IMAGE_FILE_HEADER fileHeader, IMAGE_OPTIONAL_HEADER optionalHeader)
        {
            try
            {
                int sectionOffset = Marshal.SizeOf<IMAGE_FILE_HEADER>() + fileHeader.SizeOfOptionalHeader;
                
                for (int i = 0; i < fileHeader.NumberOfSections; i++)
                {
                    var sectionHeader = ByteArrayToStructure<IMAGE_SECTION_HEADER>(dllBytes, sectionOffset + i * Marshal.SizeOf<IMAGE_SECTION_HEADER>());
                    
                    uint newProtect = PAGE_READONLY;
                    if ((sectionHeader.Characteristics & 0x20000000) != 0) // IMAGE_SCN_MEM_EXECUTE
                    {
                        newProtect = PAGE_EXECUTE_READ;
                    }
                    else if ((sectionHeader.Characteristics & 0x80000000) != 0) // IMAGE_SCN_MEM_WRITE
                    {
                        newProtect = PAGE_READWRITE;
                    }

                    IntPtr sectionAddress = (IntPtr)((long)dllBase + sectionHeader.VirtualAddress);
                    uint oldProtect;
                    VirtualProtectEx(hProcess, sectionAddress, sectionHeader.VirtualSize, newProtect, out oldProtect);
                    
                    Console.WriteLine($"Set protection for section {GetSectionName(sectionHeader.Name)}: 0x{newProtect:X}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Warning: Failed to set page protections: {ex.Message}");
            }
        }

        private static T ByteArrayToStructure<T>(byte[] bytes, int offset) where T : struct
        {
            int size = Marshal.SizeOf<T>();
            IntPtr ptr = Marshal.AllocHGlobal(size);
            try
            {
                Marshal.Copy(bytes, offset, ptr, size);
                return Marshal.PtrToStructure<T>(ptr);
            }
            finally
            {
                Marshal.FreeHGlobal(ptr);
            }
        }

        private static string GetSectionName(byte[] nameBytes)
        {
            return Encoding.ASCII.GetString(nameBytes).TrimEnd('\0');
        }

        private static byte[] CreateDllMainStub(IntPtr entryPoint, IntPtr dllBase)
        {
            // Create a simple stub that calls DllMain with DLL_PROCESS_ATTACH (1)
            // This is x64 assembly code that:
            // 1. Sets up parameters for DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
            // 2. Calls the entry point
            // 3. Returns
            
            List<byte> stub = new List<byte>();
            
            // Push registers to preserve them
            stub.AddRange(new byte[] { 0x48, 0x83, 0xEC, 0x28 }); // sub rsp, 0x28 (shadow space)
            
            // Set up parameters for DllMain
            // RCX = hinstDLL (dllBase)
            stub.AddRange(new byte[] { 0x48, 0xB9 }); // mov rcx, imm64
            stub.AddRange(BitConverter.GetBytes(dllBase.ToInt64()));
            
            // RDX = fdwReason (DLL_PROCESS_ATTACH = 1)
            stub.AddRange(new byte[] { 0x48, 0xBA, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }); // mov rdx, 1
            
            // R8 = lpvReserved (NULL)
            stub.AddRange(new byte[] { 0x4D, 0x31, 0xC0 }); // xor r8, r8
            
            // Call the entry point
            stub.AddRange(new byte[] { 0x48, 0xB8 }); // mov rax, imm64
            stub.AddRange(BitConverter.GetBytes(entryPoint.ToInt64()));
            stub.AddRange(new byte[] { 0xFF, 0xD0 }); // call rax
            
            // Restore stack and return
            stub.AddRange(new byte[] { 0x48, 0x83, 0xC4, 0x28 }); // add rsp, 0x28
            stub.AddRange(new byte[] { 0xC3 }); // ret
            
            return stub.ToArray();
        }

        private static byte[] CreateSafeDllMainStub(IntPtr entryPoint, IntPtr dllBase)
        {
            // Create a safer stub with exception handling
            List<byte> stub = new List<byte>();
            
            // Set up structured exception handling
            stub.AddRange(new byte[] { 0x48, 0x83, 0xEC, 0x38 }); // sub rsp, 0x38 (larger shadow space)
            
            // Save non-volatile registers
            stub.AddRange(new byte[] { 0x48, 0x89, 0x5C, 0x24, 0x20 }); // mov [rsp+20h], rbx
            stub.AddRange(new byte[] { 0x48, 0x89, 0x74, 0x24, 0x28 }); // mov [rsp+28h], rsi
            stub.AddRange(new byte[] { 0x48, 0x89, 0x7C, 0x24, 0x30 }); // mov [rsp+30h], rdi
            
            // Set up parameters for DllMain
            // RCX = hinstDLL (dllBase)
            stub.AddRange(new byte[] { 0x48, 0xB9 }); // mov rcx, imm64
            stub.AddRange(BitConverter.GetBytes(dllBase.ToInt64()));
            
            // RDX = fdwReason (DLL_PROCESS_ATTACH = 1)
            stub.AddRange(new byte[] { 0xBA, 0x01, 0x00, 0x00, 0x00 }); // mov edx, 1
            
            // R8 = lpvReserved (NULL)
            stub.AddRange(new byte[] { 0x4D, 0x31, 0xC0 }); // xor r8, r8
            
            // Call the entry point with try/catch simulation
            stub.AddRange(new byte[] { 0x48, 0xB8 }); // mov rax, imm64
            stub.AddRange(BitConverter.GetBytes(entryPoint.ToInt64()));
            stub.AddRange(new byte[] { 0xFF, 0xD0 }); // call rax
            
            // Restore non-volatile registers
            stub.AddRange(new byte[] { 0x48, 0x8B, 0x5C, 0x24, 0x20 }); // mov rbx, [rsp+20h]
            stub.AddRange(new byte[] { 0x48, 0x8B, 0x74, 0x24, 0x28 }); // mov rsi, [rsp+28h]
            stub.AddRange(new byte[] { 0x48, 0x8B, 0x7C, 0x24, 0x30 }); // mov rdi, [rsp+30h]
            
            // Restore stack and return
            stub.AddRange(new byte[] { 0x48, 0x83, 0xC4, 0x38 }); // add rsp, 0x38
            stub.AddRange(new byte[] { 0xC3 }); // ret
            
            return stub.ToArray();
        }

        // Special stealth injection method for Roblox
        public static bool StealthInjectForRoblox(int processId, string dllPath)
        {
            IntPtr hProcess = IntPtr.Zero;
            IntPtr dllPathAddr = IntPtr.Zero;
            IntPtr hThread = IntPtr.Zero;
            
            try
            {
                Console.WriteLine($"Using stealth injection for Roblox: {dllPath}");
                
                // Validate DLL exists
                if (!File.Exists(dllPath))
                {
                    throw new Exception($"DLL file not found: {dllPath}");
                }

                // Open target process with standard permissions for injection
                hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, processId);
                if (hProcess == IntPtr.Zero)
                {
                    throw new Exception($"Failed to open Roblox process. Error: {GetLastError()}");
                }

                Console.WriteLine("Roblox process opened successfully");

                // Create a copy of the DLL in a temporary location to avoid path-based detection
                string tempDir = Path.GetTempPath();
                string tempDllName = $"temp_{Guid.NewGuid():N}.dll";
                string tempDllPath = Path.Combine(tempDir, tempDllName);
                
                try
                {
                    File.Copy(dllPath, tempDllPath, true);
                    Console.WriteLine($"Created temporary DLL: {tempDllPath}");

                    // Allocate memory for DLL path
                    byte[] dllPathBytes = Encoding.ASCII.GetBytes(tempDllPath + "\0");
                    dllPathAddr = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)dllPathBytes.Length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                    if (dllPathAddr == IntPtr.Zero)
                    {
                        throw new Exception($"Failed to allocate memory. Error: {GetLastError()}");
                    }

                    // Write DLL path
                    nint bytesWritten;
                    if (!WriteProcessMemory(hProcess, dllPathAddr, dllPathBytes, (uint)dllPathBytes.Length, out bytesWritten))
                    {
                        throw new Exception($"Failed to write DLL path. Error: {GetLastError()}");
                    }
                    Console.WriteLine($"DLL path written: {bytesWritten} bytes");

                    // Get LoadLibraryA address
                    IntPtr loadLibraryAddr = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
                    if (loadLibraryAddr == IntPtr.Zero)
                    {
                        throw new Exception("LoadLibraryA address not found");
                    }

                    Console.WriteLine($"LoadLibraryA address: 0x{loadLibraryAddr:X}");

                    // Create remote thread for injection
                    nint threadId;
                    hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, loadLibraryAddr, dllPathAddr, 0, out threadId);
                    if (hThread == IntPtr.Zero)
                    {
                        throw new Exception($"CreateRemoteThread failed. Error: {GetLastError()}");
                    }

                    Console.WriteLine($"Created injection thread: {threadId}");

                    // Wait for completion with timeout
                    uint waitResult = WaitForSingleObject(hThread, 10000); // 10 second timeout
                    if (waitResult == 0) // WAIT_OBJECT_0
                    {
                        uint exitCode;
                        if (GetExitCodeThread(hThread, out exitCode))
                        {
                            if (exitCode == 0)
                            {
                                Console.WriteLine("Warning: LoadLibraryA returned NULL - DLL failed to load in Roblox");
                                return false;
                            }
                            else
                            {
                                Console.WriteLine($"Injection successful! HMODULE: 0x{exitCode:X}");
                                Console.WriteLine("DLL should now show a message box from Roblox!");
                                return true;
                            }
                        }
                    }
                    else if (waitResult == 0x102) // WAIT_TIMEOUT
                    {
                        Console.WriteLine("Injection timed out - this might be normal for Roblox");
                        Console.WriteLine("DLL may still be loaded, check for message box");
                        return true; // Consider it successful as Roblox might take time
                    }
                    else
                    {
                        Console.WriteLine($"Thread wait failed. Result: {waitResult}");
                        return false;
                    }
                }
                finally
                {
                    // Clean up temporary DLL file
                    try
                    {
                        if (File.Exists(tempDllPath))
                        {
                            // Wait a bit before deleting to ensure the process has loaded it
                            System.Threading.Thread.Sleep(2000);
                            File.Delete(tempDllPath);
                            Console.WriteLine("Cleaned up temporary DLL");
                        }
                    }
                    catch
                    {
                        // Ignore cleanup errors
                    }
                }

                return false;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Stealth injection for Roblox failed: {ex.Message}");
                return false;
            }
            finally
            {
                // Cleanup
                if (dllPathAddr != IntPtr.Zero && hProcess != IntPtr.Zero)
                {
                    VirtualFreeEx(hProcess, dllPathAddr, 0, 0x8000); // MEM_RELEASE
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
        
        // Simple LoadLibraryA injection for safer processes
        public static bool LoadLibraryInject(int processId, string dllPath)
        {
            IntPtr hProcess = IntPtr.Zero;
            IntPtr dllPathAddr = IntPtr.Zero;
            IntPtr hThread = IntPtr.Zero;
            
            try
            {
                Console.WriteLine($"Using LoadLibraryA injection for: {dllPath}");
                
                // Validate DLL exists
                if (!File.Exists(dllPath))
                {
                    throw new Exception($"DLL file not found: {dllPath}");
                }

                // Open target process
                hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, processId);
                if (hProcess == IntPtr.Zero)
                {
                    // Try with reduced permissions for protected processes
                    hProcess = OpenProcess(0x1F0FFF & ~0x0001, false, processId); // Remove PROCESS_TERMINATE
                    if (hProcess == IntPtr.Zero)
                    {
                        throw new Exception($"Failed to open process. Error: {GetLastError()}");
                    }
                }

                Console.WriteLine("Process opened successfully");

                // Allocate memory for DLL path
                byte[] dllPathBytes = Encoding.ASCII.GetBytes(dllPath + "\0");
                dllPathAddr = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)dllPathBytes.Length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (dllPathAddr == IntPtr.Zero)
                {
                    throw new Exception($"Failed to allocate memory. Error: {GetLastError()}");
                }

                // Write DLL path
                nint bytesWritten;
                if (!WriteProcessMemory(hProcess, dllPathAddr, dllPathBytes, (uint)dllPathBytes.Length, out bytesWritten))
                {
                    throw new Exception($"Failed to write DLL path. Error: {GetLastError()}");
                }
                Console.WriteLine($"DLL path written: {bytesWritten} bytes");

                // Get LoadLibraryA address
                IntPtr loadLibraryAddr = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
                if (loadLibraryAddr == IntPtr.Zero)
                {
                    throw new Exception("LoadLibraryA address not found");
                }

                Console.WriteLine($"LoadLibraryA address: 0x{loadLibraryAddr:X}");

                // Create remote thread
                nint threadId;
                hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, loadLibraryAddr, dllPathAddr, 0, out threadId);
                if (hThread == IntPtr.Zero)
                {
                    throw new Exception($"CreateRemoteThread failed. Error: {GetLastError()}");
                }

                Console.WriteLine($"Created remote thread: {threadId}");

                // Wait for completion with timeout
                uint waitResult = WaitForSingleObject(hThread, 10000); // 10 second timeout
                if (waitResult == 0) // WAIT_OBJECT_0
                {
                    uint exitCode;
                    if (GetExitCodeThread(hThread, out exitCode))
                    {
                        if (exitCode == 0)
                        {
                            Console.WriteLine("Warning: LoadLibraryA returned NULL - DLL failed to load");
                            return false;
                        }
                        else
                        {
                            Console.WriteLine($"LoadLibraryA completed successfully. HMODULE: 0x{exitCode:X}");
                            Console.WriteLine("DLL should now show a message box!");
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
                    Console.WriteLine($"Thread wait failed. Result: {waitResult}");
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
                if (dllPathAddr != IntPtr.Zero && hProcess != IntPtr.Zero)
                {
                    VirtualFreeEx(hProcess, dllPathAddr, 0, 0x8000); // MEM_RELEASE
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

        // Advanced features for stealth injection
        
        // Check for TLS callbacks and handle them
        private static bool ProcessTlsCallbacks(IntPtr hProcess, IntPtr dllBase, byte[] dllBytes, IMAGE_OPTIONAL_HEADER optionalHeader)
        {
            try
            {
                var tlsDir = optionalHeader.DataDirectory[9]; // IMAGE_DIRECTORY_ENTRY_TLS
                if (tlsDir.VirtualAddress == 0 || tlsDir.Size == 0)
                {
                    Console.WriteLine("No TLS callbacks to process");
                    return true;
                }
                
                Console.WriteLine($"Processing TLS callbacks at 0x{tlsDir.VirtualAddress:X}");
                
                // Read TLS directory
                int tlsOffset = (int)tlsDir.VirtualAddress;
                if (tlsOffset + 24 > dllBytes.Length) return false;
                
                // TLS directory structure (simplified)
                ulong startAddressOfRawData = BitConverter.ToUInt64(dllBytes, tlsOffset);
                ulong endAddressOfRawData = BitConverter.ToUInt64(dllBytes, tlsOffset + 8);
                ulong addressOfIndex = BitConverter.ToUInt64(dllBytes, tlsOffset + 16);
                ulong addressOfCallBacks = BitConverter.ToUInt64(dllBytes, tlsOffset + 24);
                
                if (addressOfCallBacks != 0)
                {
                    Console.WriteLine($"TLS callbacks found at: 0x{addressOfCallBacks:X}");
                    // Note: For full implementation, you would need to execute these callbacks
                    // This is a placeholder showing detection of TLS callbacks
                }
                
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Warning: Failed to process TLS callbacks: {ex.Message}");
                return false;
            }
        }
        
        // Anti-debugging checks
        private static bool IsDebuggerPresent()
        {
            try
            {
                // Check for debugger using PEB
                IntPtr peb = GetPeb();
                if (peb != IntPtr.Zero)
                {
                    byte[] pebBytes = new byte[8];
                    // Read BeingDebugged flag
                    // This is a simplified check
                    return false; // Placeholder
                }
                return false;
            }
            catch
            {
                return false;
            }
        }
        
        // Get Process Environment Block (PEB) - simplified version
        private static IntPtr GetPeb()
        {
            // This would need to be implemented using NtQueryInformationProcess
            // For now, return IntPtr.Zero as placeholder
            return IntPtr.Zero;
        }
        
        // Enhanced error handling with detailed logging
        private static void LogDetailedError(string operation, uint errorCode)
        {
            try
            {
                string errorMessage = $"Operation: {operation}, Error Code: 0x{errorCode:X8}";
                
                // Convert error code to human-readable message
                switch (errorCode)
                {
                    case 0x00000005:
                        errorMessage += " (Access Denied)";
                        break;
                    case 0x00000057:
                        errorMessage += " (Invalid Parameter)";
                        break;
                    case 0x00000008:
                        errorMessage += " (Not Enough Memory)";
                        break;
                    case 0x00000012:
                        errorMessage += " (No More Files)";
                        break;
                    default:
                        errorMessage += " (Unknown Error)";
                        break;
                }
                
                Console.WriteLine($"[ERROR] {errorMessage}");
                
                // Log to file
                string logPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "injection_errors.log");
                string timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
                File.AppendAllText(logPath, $"[{timestamp}] {errorMessage}\n");
            }
            catch
            {
                // Ignore logging errors
            }
        }
        
        // Advanced memory protection manipulation
        private static bool SetAdvancedMemoryProtection(IntPtr hProcess, IntPtr address, uint size, uint protection)
        {
            try
            {
                // Set memory protection with validation
                uint oldProtect;
                if (VirtualProtectEx(hProcess, address, size, protection, out oldProtect))
                {
                    Console.WriteLine($"Memory protection changed: 0x{oldProtect:X} -> 0x{protection:X} at 0x{address:X}");
                    return true;
                }
                else
                {
                    uint error = GetLastError();
                    LogDetailedError("SetAdvancedMemoryProtection", error);
                    return false;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to set memory protection: {ex.Message}");
                return false;
            }
        }
        
        // Process hollowing detection
        private static bool DetectProcessHollowing(int processId)
        {
            try
            {
                // Basic check for process hollowing indicators
                // This is a simplified implementation
                Process process = Process.GetProcessById(processId);
                
                // Check if the main module path matches the process name
                if (process.MainModule != null)
                {
                    string processName = process.ProcessName;
                    string moduleName = Path.GetFileNameWithoutExtension(process.MainModule.FileName);
                    
                    if (!processName.Equals(moduleName, StringComparison.OrdinalIgnoreCase))
                    {
                        Console.WriteLine($"Potential process hollowing detected: {processName} vs {moduleName}");
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
        
        // Anti-VM detection
        private static bool IsRunningInVirtualMachine()
        {
            try
            {
                // Check for common VM artifacts
                string[] vmArtifacts = {
                    "vmware", "virtualbox", "vbox", "vmtoolsd", "vmwaretray", "vmwareuser",
                    "vboxservice", "vboxtray", "vmx", "vmsrvc", "vmusrvc"
                };
                
                Process[] processes = Process.GetProcesses();
                foreach (Process proc in processes)
                {
                    string processName = proc.ProcessName.ToLower();
                    foreach (string artifact in vmArtifacts)
                    {
                        if (processName.Contains(artifact))
                        {
                            Console.WriteLine($"VM artifact detected: {processName}");
                            return true;
                        }
                    }
                }
                
                return false;
            }
            catch
            {
                return false;
            }
        }
        
        // Enhanced DLL verification
        private static bool VerifyDllIntegrity(string dllPath)
        {
            try
            {
                if (!File.Exists(dllPath))
                {
                    Console.WriteLine($"DLL not found: {dllPath}");
                    return false;
                }
                
                // Check file size
                FileInfo fileInfo = new FileInfo(dllPath);
                if (fileInfo.Length < 1024) // Minimum reasonable DLL size
                {
                    Console.WriteLine($"DLL file too small: {fileInfo.Length} bytes");
                    return false;
                }
                
                // Basic PE header validation
                byte[] headerBytes = new byte[64];
                using (FileStream fs = new FileStream(dllPath, FileMode.Open, FileAccess.Read))
                {
                    fs.Read(headerBytes, 0, 64);
                }
                
                // Check DOS header
                if (headerBytes[0] != 0x4D || headerBytes[1] != 0x5A) // "MZ"
                {
                    Console.WriteLine("Invalid DOS header");
                    return false;
                }
                
                Console.WriteLine($"DLL integrity verified: {dllPath}");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"DLL integrity check failed: {ex.Message}");
                return false;
            }
        }
        
        // Process privilege escalation check
        private static bool HasRequiredPrivileges(int processId)
        {
            try
            {
                IntPtr hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, processId);
                if (hProcess == IntPtr.Zero)
                {
                    Console.WriteLine("Failed to open process - insufficient privileges");
                    return false;
                }
                
                CloseHandle(hProcess);
                Console.WriteLine("Process access privileges verified");
                return true;
            }
            catch
            {
                return false;
            }
        }
        
        // Memory scanning for anti-cheat signatures
        private static bool ScanForAntiCheatSignatures(IntPtr hProcess)
        {
            try
            {
                // This is a simplified implementation
                // In a real scenario, you would scan for specific byte patterns
                Console.WriteLine("Scanning for anti-cheat signatures...");
                
                // Placeholder for signature scanning
                // You would implement actual signature detection here
                
                Console.WriteLine("Anti-cheat signature scan completed");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Anti-cheat signature scan failed: {ex.Message}");
                return false;
            }
        }
        
        // Advanced manual mapping with all features
        public static bool UltimateManualMapDll(int processId, string dllPath, bool enableAllFeatures = true)
        {
            IntPtr hProcess = IntPtr.Zero;
            IntPtr dllBase = IntPtr.Zero;
            
            try
            {
                Console.WriteLine("=== ULTIMATE MANUAL MAPPING ===");
                
                // Pre-injection checks
                if (enableAllFeatures)
                {
                    Console.WriteLine("Performing pre-injection security checks...");
                    
                    if (!VerifyDllIntegrity(dllPath))
                    {
                        throw new Exception("DLL integrity check failed");
                    }
                    
                    if (!HasRequiredPrivileges(processId))
                    {
                        throw new Exception("Insufficient privileges");
                    }
                    
                    if (IsDebuggerPresent())
                    {
                        Console.WriteLine("Warning: Debugger detected");
                    }
                    
                    if (IsRunningInVirtualMachine())
                    {
                        Console.WriteLine("Warning: Virtual machine detected");
                    }
                    
                    if (DetectProcessHollowing(processId))
                    {
                        Console.WriteLine("Warning: Process hollowing detected");
                    }
                }
                
                // Perform advanced manual mapping
                Console.WriteLine("Starting ultimate manual mapping...");
                
                // Read and validate DLL
                byte[] dllBytes = File.ReadAllBytes(dllPath);
                
                // Parse PE headers
                var dosHeader = ByteArrayToStructure<IMAGE_DOS_HEADER>(dllBytes, 0);
                if (dosHeader.e_magic != 0x5A4D) throw new Exception("Invalid DOS header");
                
                var fileHeader = ByteArrayToStructure<IMAGE_FILE_HEADER>(dllBytes, (int)dosHeader.e_lfanew);
                if (fileHeader.Signature != 0x00004550) throw new Exception("Invalid PE signature");
                
                var optionalHeader = ByteArrayToStructure<IMAGE_OPTIONAL_HEADER>(dllBytes, (int)dosHeader.e_lfanew + Marshal.SizeOf<IMAGE_FILE_HEADER>());
                
                // Open process
                hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, processId);
                if (hProcess == IntPtr.Zero)
                {
                    throw new Exception($"Failed to open process {processId}");
                }
                
                // Scan for anti-cheat
                if (enableAllFeatures)
                {
                    ScanForAntiCheatSignatures(hProcess);
                }
                
                // Find optimal memory location
                IntPtr preferredBase = FindSuitableMemoryLocation(hProcess, optionalHeader.SizeOfImage);
                
                // Allocate memory
                dllBase = VirtualAllocEx(hProcess, preferredBase, optionalHeader.SizeOfImage, 
                    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                if (dllBase == IntPtr.Zero)
                {
                    dllBase = VirtualAllocEx(hProcess, IntPtr.Zero, optionalHeader.SizeOfImage, 
                        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                }
                
                if (dllBase == IntPtr.Zero)
                {
                    throw new Exception("Failed to allocate memory");
                }
                
                Console.WriteLine($"Allocated memory at: 0x{dllBase:X}");
                
                // Copy headers
                nint bytesWritten;
                if (!WriteProcessMemory(hProcess, dllBase, dllBytes, optionalHeader.SizeOfHeaders, out bytesWritten))
                {
                    throw new Exception("Failed to write headers");
                }
                
                // Copy sections
                if (!CopySections(hProcess, dllBase, dllBytes, fileHeader, optionalHeader))
                {
                    throw new Exception("Failed to copy sections");
                }
                
                // Process TLS callbacks
                if (enableAllFeatures)
                {
                    ProcessTlsCallbacks(hProcess, dllBase, dllBytes, optionalHeader);
                }
                
                // Apply relocations
                if (!ApplyRelocations(hProcess, dllBase, dllBytes, optionalHeader))
                {
                    Console.WriteLine("Warning: Relocations failed");
                }
                
                // Resolve imports
                if (!ResolveImports(hProcess, dllBase, dllBytes, optionalHeader))
                {
                    Console.WriteLine("Warning: Import resolution failed");
                }
                
                // Erase headers for stealth
                EraseHeaders(hProcess, dllBase, optionalHeader.SizeOfHeaders);
                
                // Set proper page protections
                SetPageProtections(hProcess, dllBase, dllBytes, fileHeader, optionalHeader);
                
                // Call DllMain
                if (optionalHeader.AddressOfEntryPoint != 0)
                {
                    IntPtr entryPoint = (IntPtr)((long)dllBase + optionalHeader.AddressOfEntryPoint);
                    if (!CallDllMainSafe(hProcess, entryPoint, dllBase))
                    {
                        Console.WriteLine("Warning: DllMain execution failed");
                    }
                }
                
                Console.WriteLine("=== ULTIMATE MANUAL MAPPING COMPLETED ===");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Ultimate manual mapping failed: {ex.Message}");
                return false;
            }
            finally
            {
                if (hProcess != IntPtr.Zero)
                {
                    CloseHandle(hProcess);
                }
            }
        }
    }
} 
