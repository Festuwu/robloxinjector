using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

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

        // Constants
        const int PROCESS_ALL_ACCESS = 0x1F0FFF;
        const uint MEM_COMMIT = 0x1000;
        const uint MEM_RESERVE = 0x2000;
        const uint PAGE_READWRITE = 0x04;
        const uint PAGE_EXECUTE_READWRITE = 0x40;
        const uint PAGE_READONLY = 0x02;
        const uint PAGE_EXECUTE_READ = 0x20;
        const uint INFINITE = 0xFFFFFFFF;

        public static bool ManualMapDll(int processId, string dllPath)
        {
            try
            {
                Console.WriteLine($"Manual mapping DLL: {dllPath}");
                
                // Read the DLL file
                byte[] dllBytes = File.ReadAllBytes(dllPath);
                Console.WriteLine($"DLL size: {dllBytes.Length} bytes");

                // Parse PE headers
                var dosHeader = ByteArrayToStructure<IMAGE_DOS_HEADER>(dllBytes, 0);
                if (dosHeader.e_magic != 0x5A4D) // MZ
                {
                    throw new Exception("Invalid DOS header");
                }

                var fileHeader = ByteArrayToStructure<IMAGE_FILE_HEADER>(dllBytes, (int)dosHeader.e_lfanew);
                if (fileHeader.Signature != 0x00004550) // PE
                {
                    throw new Exception("Invalid PE header");
                }

                var optionalHeader = ByteArrayToStructure<IMAGE_OPTIONAL_HEADER>(dllBytes, (int)dosHeader.e_lfanew + Marshal.SizeOf<IMAGE_FILE_HEADER>());
                
                Console.WriteLine($"Image base: 0x{optionalHeader.ImageBase:X}");
                Console.WriteLine($"Entry point: 0x{optionalHeader.AddressOfEntryPoint:X}");
                Console.WriteLine($"Size of image: {optionalHeader.SizeOfImage} bytes");

                // Open target process
                IntPtr hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, processId);
                if (hProcess == IntPtr.Zero)
                {
                    throw new Exception($"Failed to open process. Error: {GetLastError()}");
                }

                // Allocate memory for the DLL
                IntPtr dllBase = VirtualAllocEx(hProcess, IntPtr.Zero, optionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (dllBase == IntPtr.Zero)
                {
                    throw new Exception($"Failed to allocate memory. Error: {GetLastError()}");
                }

                Console.WriteLine($"Allocated memory at: 0x{dllBase:X}");

                // Copy headers
                nint bytesWritten;
                WriteProcessMemory(hProcess, dllBase, dllBytes, optionalHeader.SizeOfHeaders, out bytesWritten);
                Console.WriteLine($"Copied headers: {bytesWritten} bytes");

                // Copy sections
                int sectionOffset = (int)dosHeader.e_lfanew + Marshal.SizeOf<IMAGE_FILE_HEADER>() + fileHeader.SizeOfOptionalHeader;
                
                for (int i = 0; i < fileHeader.NumberOfSections; i++)
                {
                    var sectionHeader = ByteArrayToStructure<IMAGE_SECTION_HEADER>(dllBytes, sectionOffset + i * Marshal.SizeOf<IMAGE_SECTION_HEADER>());
                    
                    if (sectionHeader.SizeOfRawData > 0)
                    {
                        IntPtr sectionAddress = (IntPtr)((long)dllBase + sectionHeader.VirtualAddress);
                        byte[] sectionData = new byte[sectionHeader.SizeOfRawData];
                        Array.Copy(dllBytes, sectionHeader.PointerToRawData, sectionData, 0, sectionHeader.SizeOfRawData);
                        
                        WriteProcessMemory(hProcess, sectionAddress, sectionData, (uint)sectionData.Length, out bytesWritten);
                        Console.WriteLine($"Copied section {GetSectionName(sectionHeader.Name)}: {bytesWritten} bytes at 0x{sectionAddress:X}");
                    }
                }

                // Apply relocations
                ApplyRelocations(hProcess, dllBase, dllBytes, optionalHeader);

                // Resolve imports
                ResolveImports(hProcess, dllBase, dllBytes, optionalHeader);

                // Set proper page protections
                SetPageProtections(hProcess, dllBase, dllBytes, fileHeader, optionalHeader);

                // Call entry point
                IntPtr entryPoint = (IntPtr)((long)dllBase + optionalHeader.AddressOfEntryPoint);
                Console.WriteLine($"Calling entry point at: 0x{entryPoint:X}");

                nint threadId;
                IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, entryPoint, dllBase, 0, out threadId);
                if (hThread == IntPtr.Zero)
                {
                    throw new Exception($"Failed to create remote thread. Error: {GetLastError()}");
                }

                Console.WriteLine($"Created remote thread: {threadId}");

                // Wait for completion
                uint waitResult = WaitForSingleObject(hThread, INFINITE);
                if (waitResult != 0)
                {
                    Console.WriteLine($"Warning: Thread wait failed. Result: {waitResult}");
                }

                uint exitCode;
                if (GetExitCodeThread(hThread, out exitCode))
                {
                    Console.WriteLine($"Entry point completed with exit code: {exitCode}");
                }

                Console.WriteLine("Manual mapping completed successfully!");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Manual mapping failed: {ex.Message}");
                return false;
            }
        }

        private static void ApplyRelocations(IntPtr hProcess, IntPtr dllBase, byte[] dllBytes, IMAGE_OPTIONAL_HEADER optionalHeader)
        {
            try
            {
                var relocDir = optionalHeader.DataDirectory[5]; // IMAGE_DIRECTORY_ENTRY_BASERELOC
                if (relocDir.VirtualAddress == 0 || relocDir.Size == 0)
                {
                    Console.WriteLine("No relocations to apply");
                    return;
                }

                Console.WriteLine($"Applying relocations at 0x{relocDir.VirtualAddress:X}, size: {relocDir.Size}");

                // Calculate the delta between preferred and actual base address
                long delta = (long)dllBase - (long)optionalHeader.ImageBase;
                if (delta == 0)
                {
                    Console.WriteLine("No relocations needed (loaded at preferred base)");
                    return;
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
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Warning: Failed to apply relocations: {ex.Message}");
            }
        }

        private static void ResolveImports(IntPtr hProcess, IntPtr dllBase, byte[] dllBytes, IMAGE_OPTIONAL_HEADER optionalHeader)
        {
            try
            {
                var importDir = optionalHeader.DataDirectory[1]; // IMAGE_DIRECTORY_ENTRY_IMPORT
                if (importDir.VirtualAddress == 0 || importDir.Size == 0)
                {
                    Console.WriteLine("No imports to resolve");
                    return;
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
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Warning: Failed to resolve imports: {ex.Message}");
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
    }
} 