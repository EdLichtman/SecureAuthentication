using System;
using System.Collections.Generic;
using System.Text;

namespace SecureAuthentication.Logging
{
    public class IncomingRequest
    {
        public string CallerIp { get; set; }
        public string CallerAgent { get; set; }
        public string CalledUrl { get; set; }
    }
}
