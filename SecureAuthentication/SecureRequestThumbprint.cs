using System.Net.Http;

namespace SecureAuthentication
{
    public class SecureRequestThumbprint
    {
        public HttpRequestMessage RequestMessage { get; set; }
        public string AppId { get; set; }
        public string IncomingBase64Signature { get; set; }
        public string Nonce { get; set; }
        public string RequestTimeStamp { get; set; }
    }
}
