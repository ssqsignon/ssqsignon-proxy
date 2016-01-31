using RestSharp;
using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text.RegularExpressions;
using System.Web.Http;

namespace SSQsignon
{
    public abstract class AuthProxyController : ApiController
    {
        public class AuthRequestModel
        {
            public string grant_type { get; set; }

            public string client_id { get; set; }

            public string code { get; set; }

            public string redirect_uri { get; set; }

            public string username { get; set; }

            public string password { get; set; }

            public string refresh_token { get; set; }

            public string scope { get; set; }

            public string client_secret { get; set; }
        }

        public AuthProxyController(string moduleName, string clientId, string clientSecret, bool grantTypeDetection = true)
        {
            ModuleName = moduleName;
            ClientId = clientId;
            ClientSecret = clientSecret;
            GrantTypeDetection = grantTypeDetection;
            restClient = new RestClient(string.Format("https://ssqsignon.com/{0}", moduleName));
            if (!string.IsNullOrEmpty(clientSecret))
            {
                restClient.Authenticator = new RestSharp.Authenticators.HttpBasicAuthenticator(clientId, clientSecret);
            }
        }

        public virtual dynamic Get(string command, string response_type = null, string redirect_uri = null, string client_id = null, string state = null, string scope = null)
        {
            if (command.Equals("whoami", StringComparison.InvariantCultureIgnoreCase))
            {
                return WhoAmI();
            }
            else if (command.Equals("saferedirect", StringComparison.InvariantCultureIgnoreCase))
            {
                return SafeRedirect(response_type, redirect_uri, client_id, state, scope);
            }
            return StatusCode(HttpStatusCode.NotFound);
        }

        public virtual dynamic Post(string command, AuthRequestModel model)
        {
            if (command.Equals("auth"))
            {
                return Auth(model);
            }
            return StatusCode(HttpStatusCode.NotFound);
        }

        public virtual dynamic Delete(string command)
        {
            if (nullifyTokenRegex.IsMatch(command))
            {
                return NullifyTokens(command);
            }
            return StatusCode(HttpStatusCode.NotFound);
        }

        protected virtual dynamic WhoAmI()
        {
            var request = new RestRequest("whoami", Method.GET);
            CopyAuthorizationHeader(request);

            return Proxy(request);

        }

        protected virtual dynamic SafeRedirect(string response_type, string redirectUri, string clientId, string state, string scope)
        {
            var request = new RestRequest("saferedirect", Method.GET);
            CopyAuthorizationHeader(request);
            request.Parameters.Add(new Parameter { Type = ParameterType.QueryString, Name = "response_type", Value = string.IsNullOrEmpty(response_type) ? "code" : response_type });
            if (!string.IsNullOrEmpty(redirectUri))
            {
                request.Parameters.Add(new Parameter { Type = ParameterType.QueryString, Name = "redirect_uri", Value = redirectUri });
            }
            if (!string.IsNullOrEmpty(clientId))
            {
                request.Parameters.Add(new Parameter { Type = ParameterType.QueryString, Name = "client_id", Value = clientId });
            }
            if (!string.IsNullOrEmpty(state))
            {
                request.Parameters.Add(new Parameter { Type = ParameterType.QueryString, Name = "state", Value = state });
            }
            if (!string.IsNullOrEmpty(scope))
            {
                request.Parameters.Add(new Parameter { Type = ParameterType.QueryString, Name = "scope", Value = scope });
            }

            return Proxy(request);
        }

        protected virtual dynamic Auth(AuthRequestModel model)
        {
            var request = new RestRequest("auth", Method.POST);
            if (string.IsNullOrEmpty(model.client_id))
            {
                model.client_id = ClientId;
            }
            if (string.IsNullOrEmpty(model.grant_type) && GrantTypeDetection)
            {
                model.grant_type = DetectGrantType(model);
            }
            request.AddJsonBody(model);

            return Proxy(request);
        }

        protected virtual dynamic NullifyTokens(string command)
        {
            var request = new RestRequest(command, Method.DELETE);
            CopyAuthorizationHeader(request);

            return Proxy(request);
        }

        protected virtual dynamic Proxy(RestRequest request)
        {
            var response = restClient.Execute(request);
            if (response.ErrorException == null && !string.IsNullOrEmpty(response.Content))
            {
                var responseProxy = new HttpResponseMessage(response.StatusCode);
                var mimeType = new System.Net.Mime.ContentType(response.ContentType);
                responseProxy.Content = new StringContent(response.Content, System.Text.Encoding.GetEncoding(mimeType.CharSet), mimeType.MediaType);
                return responseProxy;
            }
            else if (response.ErrorException == null)
            {
                return new HttpResponseMessage(response.StatusCode);
            }
            else
            {
                var resposneProxy = new HttpResponseMessage(HttpStatusCode.InternalServerError);
                resposneProxy.Content = new StringContent(Newtonsoft.Json.JsonConvert.SerializeObject(new { reason = response.ErrorException.Message }), System.Text.Encoding.UTF8, "application/json");
                return resposneProxy;
            }
        }

        protected virtual string DetectGrantType(AuthRequestModel model)
        {
            if (!string.IsNullOrEmpty(model.username) || !string.IsNullOrEmpty(model.password))
            {
                return "password";
            }
            if (!string.IsNullOrEmpty(model.code))
            {
                return "authorization_code";
            }
            if (!string.IsNullOrEmpty(model.refresh_token))
            {
                return "refresh_token";
            }
            return null;
        }

        protected virtual void CopyAuthorizationHeader(RestRequest request)
        {
            Request.Headers
                .Where(h => h.Key.Equals("authorization", StringComparison.InvariantCultureIgnoreCase))
                .ToList()
                .ForEach(h => h.Value.ToList().ForEach(v => request.AddHeader("Authorization", v)));
        }

        protected static Regex nullifyTokenRegex = new Regex(@"^.*/tokens$");

        protected string ModuleName { get; set; }

        protected string ClientId { get; set; }

        protected string ClientSecret { get; set; }

        protected bool GrantTypeDetection { get; set; }

        private RestClient restClient;
    }
}