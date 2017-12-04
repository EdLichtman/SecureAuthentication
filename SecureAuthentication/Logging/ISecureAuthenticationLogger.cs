using System;

namespace SecureAuthentication.Logging
{
    public interface ISecureAuthenticationLogger
    {
        void Warning(string message, Exception ex);
    }
}
