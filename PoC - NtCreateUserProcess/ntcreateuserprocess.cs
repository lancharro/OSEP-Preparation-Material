using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace PoC___NtCreateUserProcess
{
    class ntcreateuserprocess
    {
        public const uint CREATE_SUSPENDED = 0x4;
        public const UInt32 RTL_USER_PROCESS_PARAMETERS_NORMALIZED = 0x01;
        public const UInt32 PROCESS_ALL_ACCESS = 0x001fffff;
        public const UInt32 THREAD_ALL_ACCESS = 0x001fffff;
        public const UInt32 PsCreateInitialState = 0x0;
        public const UInt32 HEAP_ZERO_MEMORY = 0x8;
        public const UInt32 PS_ATTRIBUTE_IMAGE_NAME = 0x2005;
        



        internal struct PS_CREATE_INFO
        {
            public UIntPtr Size;
            public UInt32 State; 
            public UIntPtr InitState;
            public UIntPtr FailSection;
            public ushort ExeFormat;
            public UIntPtr ExeName;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 40)]
            public byte[] SuccessState;
        }





        internal struct PS_ATTRIBUTE
        {
            public UInt64 Attribute;
            public UIntPtr Size; 
            public IntPtr Value;
            public IntPtr ValuePtr;
            public IntPtr ReturnLength;
        }


        internal struct PS_ATTRIBUTE_LIST
        {
            public UIntPtr TotalLength;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public PS_ATTRIBUTE[] Attributes;
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

        
        public struct UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
//            [MarshalAs(UnmanagedType.LPWStr)]
//            public string Buffer
            public IntPtr Buffer;
        }

        /*
        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING : IDisposable
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr buffer;

            public UNICODE_STRING(string s)
            {
                Length = (ushort)(s.Length * 2);
                MaximumLength = (ushort)(Length + 2);
                buffer = Marshal.StringToHGlobalUni(s);
            }

            public void Dispose()
            {
                Marshal.FreeHGlobal(buffer);
                buffer = IntPtr.Zero;
            }

            public override string ToString()
            {
                return Marshal.PtrToStringUni(buffer);
            }
        }
        */

        /*
        public struct RTL_USER_PROCESS_PARAMETERS
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] Reserved1;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
            public IntPtr[] Reserved2;
            UNICODE_STRING ImagePathName;
            UNICODE_STRING CommandLine;
        }
        */


        public struct CURDIR
        {
            UNICODE_STRING DosPath;
            IntPtr Handle;
        }

        public struct RTL_DRIVE_LETTER_CURDIR
        {
            ushort Flags;
            ushort Length;
            ulong TimeStamp;
            string DosPath;
        }


        public struct RTL_USER_PROCESS_PARAMETERS
        {
            ulong MaximumLength;
            ulong Length;
            ulong Flags;
            ulong DebugFlags;
            IntPtr ConsoleHandle;
            ulong ConsoleFlags;
            IntPtr StandardInput;
            IntPtr StandardOutput;
            IntPtr StandardError;
            CURDIR CurrentDirectory;
            UNICODE_STRING DllPath;
            UNICODE_STRING ImagePathName;
            UNICODE_STRING CommandLine;
            IntPtr Environment;
            ulong StartingX;
            ulong StartingY;
            ulong CountX;
            ulong CountY;
            ulong CountCharsX;
            ulong CountCharsY;
            ulong FillAttribute;
            ulong WindowFlags;
            ulong ShowWindowFlags;
            UNICODE_STRING WindowTitle;
            UNICODE_STRING DesktopInfo;
            UNICODE_STRING ShellInfo;
            UNICODE_STRING RuntimeData;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
            public RTL_DRIVE_LETTER_CURDIR[] CurrentDirectores;
            ulong EnvironmentSize;
            ulong EnvironmentVersion;
            ulong PackageDependencyData;
            ulong ProcessGroupId;
            ulong LoaderThreads;
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



        [DllImport("ntdll.dll", SetLastError = true)]
        static extern UInt32 NtCreateUserProcess(
            ref IntPtr ProcessHandle, 
            ref IntPtr ThreadHandle,
            //AccessMask ProcessDesiredAccess, 
            //AccessMask ThreadDesiredAccess, 
            UInt32 ProcessDesiredAccess,
            UInt32 ThreadDesiredAccess, 
            IntPtr ProcessObjectAttributes, 
            IntPtr ThreadObjectAttributes,
            UInt32 ProcessFlags,
            UInt32 ThreadFlags,
            IntPtr ProcessParameters,
            //IntPtr CreateInfo,
            ref PS_CREATE_INFO CreateInfo,
            ref PS_ATTRIBUTE_LIST AttributeList);
            //IntPtr AttributeList);

        /*

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern UInt32 RtlCreateProcessParametersEx(
            ref IntPtr ProcessParameters,
            ref UNICODE_STRING ImagePathName,
            IntPtr DllPath,
            ref UNICODE_STRING CurrentDirectory,
            ref UNICODE_STRING CommandLine,
            IntPtr Environment,
            ref UNICODE_STRING WindowTitle,
            ref UNICODE_STRING DesktopInfo,
            IntPtr ShellInfo,
            IntPtr RuntimeData,
            UInt32 Flags);
        */
        [DllImport("ntdll.dll", SetLastError = true)]
        static extern UInt32 RtlCreateProcessParametersEx(
            ref IntPtr ProcessParameters,
            ref UNICODE_STRING ImagePathName,
            IntPtr DllPath,
            IntPtr CurrentDirectory,
            IntPtr CommandLine,
            IntPtr Environment,
            IntPtr WindowTitle,
            IntPtr DesktopInfo,
            IntPtr ShellInfo,
            IntPtr RuntimeData,
            UInt32 Flags);


        [DllImport("ntdll.dll")]
        public static extern void RtlInitUnicodeString(
          ref UNICODE_STRING DestinationString,
          [MarshalAs(UnmanagedType.LPWStr)] string SourceString);



        [DllImport("ntdll.dll")]
        public static extern IntPtr RtlAllocateHeap(
          IntPtr HeapHandle,
          UInt32 Flags,
          UIntPtr Size);


       
        [DllImport("kernel32.dll")]
        static extern IntPtr GetProcessHeap();
        



        static void Main(string[] args)
        {
            //Run host process
            /*
            STARTUPINFO si = new STARTUPINFO();
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            bool res = CreateProcess(null, "C:\\Windows\\System32\\calc.exe", IntPtr.Zero, IntPtr.Zero, false, 0, IntPtr.Zero, null, ref si, out pi);
            if (res == false)
            {
                Console.WriteLine("CreateProcess failed");
                return;
            }
            Console.WriteLine("Process ID: " + pi.dwProcessId);
            Console.WriteLine("Thread ID: " + pi.dwThreadId);
            */

            /**************************************************************/
            UNICODE_STRING NtImagePath = new UNICODE_STRING();


            UIntPtr size_unicode_string  = (UIntPtr)Marshal.SizeOf(typeof(UNICODE_STRING));
            UIntPtr size_ptrl_user_process_parameters = (UIntPtr)Marshal.SizeOf(typeof(RTL_USER_PROCESS_PARAMETERS));


            RtlInitUnicodeString(ref NtImagePath, "C:\\Windows\\System32\\calc.exe");


            ushort ntimagepath = NtImagePath.Length;
            ushort ntimagelen = NtImagePath.MaximumLength;
            IntPtr ntimagemax = NtImagePath.Buffer;

            Console.WriteLine("[+] RtlInitUnicodeString executed...");


            
            IntPtr pProcessParameters = IntPtr.Zero;
            IntPtr DllPath = IntPtr.Zero;
            IntPtr CurrentDirectory = IntPtr.Zero;
            IntPtr CommandLine = IntPtr.Zero;
            IntPtr Environment = IntPtr.Zero;
            IntPtr WindowTitle = IntPtr.Zero;
            IntPtr DesktopInfo = IntPtr.Zero;
            IntPtr ShellInfo = IntPtr.Zero;
            IntPtr RuntimeData = IntPtr.Zero;

            UInt32 res = RtlCreateProcessParametersEx(ref pProcessParameters, ref NtImagePath, DllPath, CurrentDirectory, CommandLine, Environment, WindowTitle, DesktopInfo, ShellInfo, RuntimeData, RTL_USER_PROCESS_PARAMETERS_NORMALIZED);
            Console.WriteLine("[+] RtlCreateProcessParametersEx return: 0x" + String.Format("{0:X}", res));
            Console.WriteLine("[+] pProcessParameters: 0x" + String.Format("{0:X}", (pProcessParameters).ToInt64()));

            PS_CREATE_INFO CreateInfo = new PS_CREATE_INFO();
            //CreateInfo.Size = (UIntPtr)Marshal.SizeOf(typeof(PS_CREATE_INFO));
            CreateInfo.Size = (UIntPtr)Marshal.SizeOf(typeof(PS_CREATE_INFO));
            CreateInfo.State = PsCreateInitialState;

            int CreateInfoSize = Marshal.SizeOf(typeof(PS_CREATE_INFO));
            IntPtr pCreateInfo = Marshal.AllocHGlobal(CreateInfoSize);
            Marshal.StructureToPtr(CreateInfo, pCreateInfo, true);


            IntPtr hProcessHeap = IntPtr.Zero;
            hProcessHeap = GetProcessHeap();
            UIntPtr heapSize = (UIntPtr)Marshal.SizeOf(typeof(PS_ATTRIBUTE));
            IntPtr pAttributeList = RtlAllocateHeap(hProcessHeap, HEAP_ZERO_MEMORY, heapSize);
            Console.WriteLine("[+] RtlAllocateHeap return: 0x"+ String.Format("{0:X}", (pAttributeList).ToInt64()));

            PS_ATTRIBUTE_LIST AttributeList = new PS_ATTRIBUTE_LIST();
            AttributeList = (PS_ATTRIBUTE_LIST)Marshal.PtrToStructure(pAttributeList, typeof(PS_ATTRIBUTE_LIST));
            UIntPtr ps_attribute_list_size = (UIntPtr)(Marshal.SizeOf(typeof(PS_ATTRIBUTE_LIST)));
            UIntPtr ps_attribute_size = (UIntPtr)(Marshal.SizeOf(typeof(PS_ATTRIBUTE)));
            AttributeList.TotalLength = (UIntPtr)(Marshal.SizeOf(typeof(PS_ATTRIBUTE_LIST)) - Marshal.SizeOf(typeof(PS_ATTRIBUTE)));
            AttributeList.Attributes[0].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
            AttributeList.Attributes[0].Size = (UIntPtr)NtImagePath.Length;
            AttributeList.Attributes[0].Value = NtImagePath.Buffer;
            AttributeList.Attributes[0].ValuePtr = NtImagePath.Buffer;
            AttributeList.Attributes[0].ReturnLength = (IntPtr)0x0;
            AttributeList.Attributes[1].Attribute = 0x0;
            AttributeList.Attributes[1].Size = (UIntPtr)0x0;
            AttributeList.Attributes[1].Value = (IntPtr)0x0;
            AttributeList.Attributes[1].ValuePtr = (IntPtr)0x0;
            AttributeList.Attributes[1].ReturnLength = (IntPtr)0x0;

            int AttributeListSize = Marshal.SizeOf(typeof(PS_ATTRIBUTE_LIST));
            IntPtr pAttributeList2 = Marshal.AllocHGlobal(AttributeListSize);
            Marshal.StructureToPtr(AttributeList, pAttributeList2, true);




            IntPtr hProcess = IntPtr.Zero;
            IntPtr hThread = IntPtr.Zero;
            UInt32 ProcessFlags = 0;
            UInt32 ThreadFlags = 0;
            UInt32 res2 = NtCreateUserProcess(ref hProcess, ref hThread, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, IntPtr.Zero, IntPtr.Zero, ProcessFlags, ThreadFlags, pProcessParameters, ref CreateInfo, ref AttributeList);
            //NtCreateUserProcess(&hProcess, &hThread, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, NULL, NULL, 0, 0, pProcessParameters, &CreateInfo, AttributeList);
            Console.WriteLine("Process ID: " + hProcess);
            Console.WriteLine("Thread ID: " + hThread);

        }
    }
}
