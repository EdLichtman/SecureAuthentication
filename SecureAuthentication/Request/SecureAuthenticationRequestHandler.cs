using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Configuration;
using System.Net;
using System.Web;

namespace SecureAuthentication.Request
{
    public class SecureAuthenticationRequestHandler : DelegatingHandler
    {
        //Obtained from the server earlier, _apiKey MUST be stored securely and in App.Config
        private readonly string _appId;
        private readonly string _apiKey;
        private readonly string _scheme;

        public SecureAuthenticationRequestHandler(string appId, string apiKey, string applicationSchema)
        {
            _appId = appId;
            _apiKey = apiKey;
            _scheme = applicationSchema;
        }

        protected async override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {

            request = await HandleRequest(request);

            var response = await base.SendAsync(request, cancellationToken);

            return response;
        }

        protected async Task<HttpRequestMessage> HandleRequest(HttpRequestMessage request)
        {

            string requestContentBase64String = string.Empty;

            string requestUri = WebUtility.UrlEncode(request.RequestUri.AbsoluteUri.ToLower());

            string requestHttpMethod = request.Method.Method;

            //Calculate UNIX time
            DateTime epochStart = new DateTime(1970, 01, 01, 0, 0, 0, 0, DateTimeKind.Utc);
            TimeSpan timeSpan = DateTime.UtcNow - epochStart;
            string requestTimeStamp = Convert.ToUInt64(timeSpan.TotalSeconds).ToString();

            //create random nonce for each request
            string nonce = Guid.NewGuid().ToString("N");

            //Checking if the request contains body, usually will be null wiht HTTP GET and DELETE
            if (request.Content != null)
            {
                byte[] content = await request.Content.ReadAsByteArrayAsync();
                MD5 md5 = MD5.Create();
                //Hashing the request body, any change in request body will result in different hash, we'll incure message integrity
                byte[] requestContentHash = md5.ComputeHash(content);
                requestContentBase64String = Convert.ToBase64String(requestContentHash);
            }

            //Creating the raw signature string
            string signatureRawData = String.Format("{0}{1}{2}{3}{4}{5}", _appId, requestHttpMethod, requestUri, requestTimeStamp, nonce, requestContentBase64String);

            var secretKeyByteArray = Convert.FromBase64String(_apiKey);

            byte[] signature = Encoding.UTF8.GetBytes(signatureRawData);

            using (HMACSHA256 hmac = new HMACSHA256(secretKeyByteArray))
            {
                byte[] signatureBytes = hmac.ComputeHash(signature);
                string requestSignatureBase64String = Convert.ToBase64String(signatureBytes);
                //Setting the values in the Authorization header using custom scheme 
                var customScheme = _scheme;
                request.Headers.Authorization = new AuthenticationHeaderValue(customScheme, string.Format("{0}:{1}:{2}:{3}", _appId, requestSignatureBase64String, nonce, requestTimeStamp));
            }

            return request;
        }
    }
}
