using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecureAuthentication.Credentials
{
    public interface IApplicationCredentialsConfiguration
    {
        string GetApplicationSchema();
        IList<ApplicationCredentials> GetApplicationCredentials();
    }
}
