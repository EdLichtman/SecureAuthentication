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
    }
}
