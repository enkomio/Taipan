using System;
using System.IO;

namespace TestSSLServerLib
{
    public sealed class FullTestWrapper
    {
        private readonly FullTest _fullTest = new FullTest();

        public Boolean AllSuites { get; set; }
        public String ServerName { get; set; }
        public Int32 ServerPort { get; set; }
        public String ProxName { get; set; }
        public Int32 ProxPort { get; set; }
        public Boolean ShowCertPEM { get; set; }

        public String Run()
        {
            var stringWriter = new StringWriter();
            var json = new JSON(stringWriter);
            
            _fullTest.AllSuites = this.AllSuites;
            _fullTest.ServerName = this.ServerName;
            _fullTest.ServerPort = this.ServerPort;
            _fullTest.ProxName = this.ProxName;
            _fullTest.ProxPort = this.ProxPort;

            // default option
            _fullTest.ReadTimeout = 20000;
            _fullTest.ConnectionWait = 0;
            _fullTest.AddECExt = true;

            var report = _fullTest.Run();
            report.ShowCertPEM = this.ShowCertPEM;
                        
            report.Print(json);
            return stringWriter.ToString();
        }
    }
}
