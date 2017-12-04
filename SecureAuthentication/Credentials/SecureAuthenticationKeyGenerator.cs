using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SecureAuthentication.Credentials
{
    public class SecureAuthenticationKeyGenerator
    {   

        public static string GenerateAppId()
        {
            return Guid.NewGuid().ToString("N");
        }

        public static string GenerateApiKey()
        {
            return GenerateRandomBase64Key();
        }
        private static string GenerateRandomBase64Key()
        {
            using (var cryptoProvider = new RNGCryptoServiceProvider())
            {
                byte[] secretKeyByteArray = new byte[32];
                cryptoProvider.GetBytes(secretKeyByteArray);
                return Convert.ToBase64String(secretKeyByteArray);
            }
        }
    }
}
