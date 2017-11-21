using System;

namespace HMACAuthenticationFilter
{
    public interface ILogger
    {
        void Warning(string message, Exception ex);
    }
}
