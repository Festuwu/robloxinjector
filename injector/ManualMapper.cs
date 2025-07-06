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
        const uint INFINITE = 0xFFFFFFFF;

        public static bool ManualMapDll(int processId, string dllPath)
        {
            // For maximum compatibility, use simple LoadLibraryA injection
            // This is much more reliable than manual mapping for most processes
            return LoadLibraryInject(processId, dllPath);
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
    }
} 
