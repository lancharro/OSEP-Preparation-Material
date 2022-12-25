using System;
using System.Data.SqlClient;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MSSQL___Linked_Servers_Query
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

            //Query Version on a linked server (DC01)
            //String execCmd = "select version from openquery(\"dc01\", 'select @@version as version');";
            //SqlCommand command = new SqlCommand(execCmd, con);
            //SqlDataReader reader = command.ExecuteReader();            
            //reader.Read();
            //Console.WriteLine("Linked SQL server: " + reader[0]);
            //reader.Close();

            String localCmd = "select SYSTEM_USER;";
            String execCmd = "select myuser from openquery(\"dc01\", 'select SYSTEM_USER as myuser');";

            SqlCommand command = new SqlCommand(localCmd, con);
            SqlDataReader reader = command.ExecuteReader();            
            reader.Read();
            Console.WriteLine("Executing as the login: " + reader[0] + " on APPSRV01");
            reader.Close();

            command = new SqlCommand(execCmd, con);
            reader = command.ExecuteReader();
            reader.Read();
            Console.WriteLine("Executing as the login: " + reader[0] + " on DC01");
            reader.Close();

            con.Close();
        }
    }
}