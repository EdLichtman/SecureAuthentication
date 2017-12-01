using System;
using System.Collections.Generic;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Http.Filters;
using System.Net.Http;
using System.Web.Http.Results;
using System.Web;
using System.Security.Cryptography;
using Newtonsoft.Json;
using System.Runtime.Caching;
using System.Web.Http;
using System.Net;
using System.Net.Http.Headers;
using System.Configuration;
using SecureAuthentication;

namespace SecureAuthentication
{
    public class SecureAuthenticationAttribute: Attribute, IAuthenticationFilter
    {
        const int AppIdIndex = 0;
        const int IncomingHashedSignatureIndex = 1;
        const int NonceIndex = 2;
        const int RequestTimeStampIndex = 3;

        private static readonly Dictionary<string, string> AllowedApps = new Dictionary<string, string>();

        private readonly UInt64 requestMaxAgeInSeconds = 300;  //5 mins
        private readonly string _authenticationScheme;
        private readonly ILogger _logger;

        private HttpRequestMessage _currentRequest;
        private HttpAuthenticationContext _currentContext;

              public SecureAuthenticationAttribute(Type typeOfApplicationCredentialsConfig, Type typeOfLogger)
        {
            var applicationConfiguration = Activator.CreateInstance(typeOfApplicationCredentialsConfig) as IApplicationCredentialsConfiguration;
            if (applicationConfiguration == null)
                throw new InvalidCastException("ApplicationCredentials Type must inherit from ILogger in NuGet Package");
            _authenticationScheme = applicationConfiguration.GetApplicationSchema();
            var appCredentials = applicationConfiguration.GetApplicationCredentials();

            ILogger logger = Activator.CreateInstance(typeOfLogger) as ILogger;
            if (logger == null)
                throw new InvalidCastException("Logger Type must inherit from ILogger in NuGet Package");
            _logger = logger;

            var allowedAppCredentials = new Dictionary<string, string>();
            foreach(var appCredential in appCredentials)
            {
                var appId = appCredential.AppId;
                var apiKey = appCredential.ApiKey;

                if (!AllowedApps.ContainsKey(appId))
                    AllowedApps.Add(appId, apiKey);
            }
        }

        public Task AuthenticateAsync(HttpAuthenticationContext context, CancellationToken cancellationToken)
        {
            _currentContext = context;
            _currentRequest = context.Request;
            var authorizationHeaders = GetAuthorizationHeaders(_currentRequest);
            var isAuthenticated = CheckAuthentication(_currentRequest, authorizationHeaders);

            if (isAuthenticated)
            {
                var appId = authorizationHeaders[AppIdIndex];
                var currentPrincipal = new GenericPrincipal(new GenericIdentity(appId), null);
                context.Principal = currentPrincipal;
            }
            else
                context.ErrorResult = new NotFoundResult(context.Request);


            return Task.FromResult(0);
        }

        protected string[] GetAuthorizationHeaders(HttpRequestMessage req)
        {
            if (req.Headers.Authorization != null &&
                _authenticationScheme.Equals(req.Headers.Authorization.Scheme, StringComparison.OrdinalIgnoreCase))
            {
                var rawAuthorizationHeader = req.Headers.Authorization.Parameter;

                return GetAuthorizationHeaderValues(rawAuthorizationHeader);
            }
            return null;
        }
        protected bool CheckAuthentication(HttpRequestMessage req, string[] authorizationHeaderValues)
        {

            if (authorizationHeaderValues != null)
            {
                var appId = authorizationHeaderValues[AppIdIndex];
                var incomingBase64Signature = authorizationHeaderValues[IncomingHashedSignatureIndex];
                var nonce = authorizationHeaderValues[NonceIndex];
                var requestTimeStamp = authorizationHeaderValues[RequestTimeStampIndex];
                var requestThumbprint = new SecureRequestThumbprint
                {
                    AppId = appId,
                    RequestMessage = req,
                    IncomingBase64Signature = incomingBase64Signature,
                    Nonce = nonce,
                    RequestTimeStamp = requestTimeStamp
                };

                var isValid = IsValidRequest(requestThumbprint);

                if (isValid.Result)
                {
                    return true;
                }

                LogUnauthorized(requestThumbprint);
                return false;
            }

            LogNoHeaders();
            return false;

        }

        private void LogUnauthorized(object thumbprint)
        {
            if (_currentRequest != null)
            {
                var userAccessDetails = JsonConvert.SerializeObject(GetCallerLogDetails());
                var stringifiedThumbprint = JsonConvert.SerializeObject(thumbprint);
                var unauthorizedAccessException = new UnauthorizedAccessException($"Invalid Request from: {userAccessDetails}; Request Thumbprint: {stringifiedThumbprint}");
                _logger.Warning("APIACCESS: Invalid Request came in", unauthorizedAccessException);
            }
        }

        private void LogNoHeaders()
        {
            if (_currentRequest != null)
            {
                var userAccessDetails = JsonConvert.SerializeObject(GetCallerLogDetails());
                var invalidHeaderException = new UnauthorizedAccessException($"No Thumbprint detected. Invalid Request from: {userAccessDetails}");
                _logger.Warning("APIACCESS: Invalid Request came in", invalidHeaderException);
            }
        }

        public Task ChallengeAsync(HttpAuthenticationChallengeContext context, CancellationToken cancellationToken)
        {
            context.Result = new ResultWithChallenge(context.Result, _authenticationScheme);
            return Task.FromResult(0);
        }

        public bool AllowMultiple
        {
            get { return false; }
        }

        private string[] GetAuthorizationHeaderValues(string rawAuthzHeader)
        {

            var credArray = rawAuthzHeader.Split(':');

            if (credArray.Length == 4)
            {
                return credArray;
            }
            else
            {
                return null;
            }

        }
        protected async Task<bool> IsValidRequest(SecureRequestThumbprint request)
        {
            string requestContentBase64String = "";
            string requestUri = HttpUtility.UrlEncode(request.RequestMessage.RequestUri.AbsoluteUri.ToLower());
            string requestHttpMethod = request.RequestMessage.Method.Method;

            if (!AllowedApps.ContainsKey(request.AppId))
            {
                return false;
            }

            var sharedKey = AllowedApps[request.AppId];

            if (IsReplayRequest(request.Nonce, request.RequestTimeStamp))
            {
                return false;
            }

            byte[] hash = await ComputeHash(request.RequestMessage.Content);

            if (hash != null)
            {
                requestContentBase64String = Convert.ToBase64String(hash);
            }

            string data = String.Format("{0}{1}{2}{3}{4}{5}", request.AppId, requestHttpMethod, requestUri, request.RequestTimeStamp, request.Nonce, requestContentBase64String);

            var secretKeyBytes = Convert.FromBase64String(sharedKey);

            byte[] signature = Encoding.UTF8.GetBytes(data);

            using (HMACSHA256 hmac = new HMACSHA256(secretKeyBytes))
            {
                byte[] signatureBytes = hmac.ComputeHash(signature);

                return (request.IncomingBase64Signature.Equals(Convert.ToBase64String(signatureBytes), StringComparison.Ordinal));
            }

        }

        private bool IsReplayRequest(string nonce, string requestTimeStamp)
        {
            if (MemoryCache.Default.Contains(nonce))
            {
                return true;
            }

            DateTime epochStart = new DateTime(1970, 01, 01, 0, 0, 0, 0, DateTimeKind.Utc);
            TimeSpan currentTs = DateTime.UtcNow - epochStart;

            var serverTotalSeconds = Convert.ToUInt64(currentTs.TotalSeconds);
            var requestTotalSeconds = Convert.ToUInt64(requestTimeStamp);

            if ((serverTotalSeconds - requestTotalSeconds) > requestMaxAgeInSeconds)
            {
                return true;
            }

            MemoryCache.Default.Add(nonce, requestTimeStamp, DateTimeOffset.UtcNow.AddSeconds(requestMaxAgeInSeconds));

            return false;
        }

        private static async Task<byte[]> ComputeHash(HttpContent httpContent)
        {


            using (MD5 md5 = MD5.Create())
            {
                byte[] hash = null;
                if (httpContent != null)
                {
                    var content = await httpContent.ReadAsByteArrayAsync();
                    if (content.Length != 0)
                    {
                        hash = md5.ComputeHash(content);
                    }
                }
                return hash;
            }
        }

        private IncomingRequest GetCallerLogDetails()
        {
            return new IncomingRequest
            {
                //CallerIp = _currentContext.,
                CallerAgent = _currentRequest.Headers.UserAgent.ToString(),
                CalledUrl = _currentRequest.RequestUri.ToString()
            };

        }
    }
    public class ResultWithChallenge : IHttpActionResult
    {
        private readonly string _authenticationScheme;
        private readonly IHttpActionResult _next;

        public ResultWithChallenge(IHttpActionResult next, string authenticationScheme)
        {
            _next = next;
            _authenticationScheme = authenticationScheme;
        }

        public async Task<HttpResponseMessage> ExecuteAsync(CancellationToken cancellationToken)
        {
            var response = await _next.ExecuteAsync(cancellationToken);

            if (response.StatusCode == HttpStatusCode.Unauthorized)
            {
                response.Headers.WwwAuthenticate.Add(new AuthenticationHeaderValue(_authenticationScheme));
            }

            return response;
        }
    }
}
