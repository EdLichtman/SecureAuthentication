using System;
using SecureAuthentication.Logging;

namespace SecureAuthentication.Unit.Tests
{
    internal class TestLogger : ISecureAuthenticationLogger
    {
        public void Warning(string message, Exception ex)
        {
            throw new NotImplementedException();
        }
    }
}
