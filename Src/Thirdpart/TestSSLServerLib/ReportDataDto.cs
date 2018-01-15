using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TestSSLServerLib
{
    public class ReportDataDto
    {
        public Boolean WeakCipher { get; set; }
        public Boolean NameMismatch { get; set; }
        public List<String> Issues { get; private set; }

        public ReportDataDto()
        {
            this.Issues = new List<String>();
            this.NameMismatch = false;
            this.WeakCipher = false;
        }
    }
}
