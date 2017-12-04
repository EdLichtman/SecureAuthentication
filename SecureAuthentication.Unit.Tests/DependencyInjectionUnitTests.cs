using NUnit.Framework;
using SecureAuthentication.Filter;
using System.Web.Http;

namespace SecureAuthentication.Unit.Tests
{
    [TestFixture]
    internal class DependencyInjectionUnitTests
    {
        [Test]
        public void Can_use_attribute_with_proper_interface_implementation()
        {
            var attribute = new SecureAuthenticationAttribute(typeof(TestCredentialsConfig), typeof(TestLogger));
            Assert.That(attribute, Is.Not.Null);
        }

        [Test]
        public void Cannot_use_attribute_without_proper_interface_implementation()
        {
            SecureAuthenticationAttribute attribute = null;
            try
            {
                attribute = new SecureAuthenticationAttribute(typeof(string),typeof(string));
            }catch
            {
                /*do nothing. We expect that this object 
                 * can't be instantiated with types 
                 * that don't implement required Interfaces*/
            }
            Assert.That(attribute, Is.Null);
        }
    }

    [SecureAuthentication(typeof(TestCredentialsConfig),typeof(TestLogger))]
    public class ValidAttributeImplementationController: ApiController
    {
        
    }

    [SecureAuthentication(typeof(string), typeof(string))]
    public class InvalidAttributeImplementationController : ApiController
    {

    }
}
