using System;

namespace SecureAuthentication
{
    public interface ILogger
    {
        void Warning(string message, Exception ex);
    }
}
