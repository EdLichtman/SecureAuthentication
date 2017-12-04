using System;
using SecureAuthentication.Credentials;

namespace SecureAuthentication.Filter
{
    public class DefaultSecureAuthenticationAttribute : SecureAuthenticationAttribute
    {
        public DefaultSecureAuthenticationAttribute() 
            : base(typeof(DefaultApplicationCredentialConfiguration))
        {
        }

        public DefaultSecureAuthenticationAttribute(Type typeOfLogger) 
            : base(typeof(DefaultApplicationCredentialConfiguration), typeOfLogger)
        {
        }
    }
}
