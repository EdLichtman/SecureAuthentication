using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace SecureAuthentication.Request
{
    public class SecureAuthenticationRequest
    {
        private SecureAuthenticationRequestHandler _handler;
        private HttpClient _client;
        public string BaseUri { get; set; } = "";
        public SecureAuthenticationRequest(string appId, string apiKey, string applicationSchema)
        {
            _handler = new SecureAuthenticationRequestHandler(appId, apiKey, applicationSchema);
            _client = HttpClientFactory.Create(_handler);
        }

        public async Task<HttpResponseMessage> GetAsync(string endpoint)
        {
            return await _client.GetAsync($"{BaseUri}/{endpoint}");
        }
        
        public async Task<HttpResponseMessage> PostJsonAsync(string endpoint, object body)
        {

            return await _client.PostAsJsonAsync<object>($"{BaseUri}/{endpoint}", body);
        }
        
    }
}
