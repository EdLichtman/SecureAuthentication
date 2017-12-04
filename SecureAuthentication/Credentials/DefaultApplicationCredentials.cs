using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecureAuthentication.Credentials
{
    public class DefaultApplicationCredentialConfiguration : IApplicationCredentialsConfiguration
    {
        public IList<ApplicationCredentials> GetApplicationCredentials()
        {
            return new List<ApplicationCredentials>
            {
                new ApplicationCredentials
                {
                    AppId = ConfigurationManager.AppSettings["appId"],
                    ApiKey = ConfigurationManager.AppSettings["apiKey"]
                }
            };
        }

        public string GetApplicationSchema()
        {
            return ConfigurationManager.AppSettings["appSchema"];
        }
    }
}
