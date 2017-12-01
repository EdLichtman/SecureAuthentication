using System.Collections.Generic;
using SecureAuthentication;

namespace SecureAuthentication.Unit.Tests
{
    internal class TestCredentialsConfig : IApplicationCredentialsConfiguration
    {
        public IList<ApplicationCredentials> GetApplicationCredentials()
        {
            return new List<ApplicationCredentials>
            {
                new ApplicationCredentials
                {
                    ApiKey = "foo",
                    AppId = "bar"
                }
            };
        }

        public string GetApplicationSchema()
        {
            return "foo";
        }
    }
}
