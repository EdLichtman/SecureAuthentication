using System;
using SecureAuthentication;

namespace SecureAuthentication.Unit.Tests
{
    internal class TestLogger : ILogger
    {
        public void Warning(string message, Exception ex)
        {
            throw new NotImplementedException();
        }
    }
}
