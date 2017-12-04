using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecureAuthentication.Logging
{
    public class DummySecureAuthenticationLogger : ISecureAuthenticationLogger
    {
        public void Warning(string message, Exception ex)
        {
            //do nothing
        }
    }
}
