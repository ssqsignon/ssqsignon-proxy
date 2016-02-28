using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using Nancy.ModelBinding;
using RestSharp;

namespace SSQSignon
{
    public abstract class AuthProxyModule : Nancy.NancyModule
    {
        public AuthProxyModule(string path, string moduleName, string clientId, string clientSecret, bool detectGrantType = true)
        {
            if (string.IsNullOrEmpty(path))
            {
                throw new ArgumentNullException("path");
            }
            if (string.IsNullOrEmpty(moduleName))
            {
                throw new ArgumentNullException("moduleName");
            }
            if (string.IsNullOrEmpty(clientId))
            {
                throw new ArgumentNullException("clientId");
            }

            var restClient = new RestClient(string.Format("https://ssqsignon.com/{0}", moduleName));
            if (!string.IsNullOrEmpty(clientSecret))
            {
                restClient.Authenticator = new RestSharp.Authenticators.HttpBasicAuthenticator(clientId, clientSecret);
            }

            Post[string.Format("{0}/auth", path)] = _ =>
            {
                try
                {
                    var request = this.Bind<AuthRequest>();
                    return Auth(restClient, request, clientId, detectGrantType);
                }
                catch (Nancy.ModelBinding.ModelBindingException)
                {
                    return Send(Nancy.HttpStatusCode.BadRequest, new { error = "request_body_invalid" });
                }
            };

            Get[string.Format("{0}/whoami", path)] = _ =>
            {
                return WhoAmI(restClient);
            };

            Get[string.Format("{0}/saferedirect", path)] = _ =>
            {
                return SafeRedirect(restClient, Request.Query.response_type, Request.Query.redirect_uri, Request.Query.client_id, Request.Query.state, Request.Query.scope, Request.Query.deny_access);
            };

            Delete[string.Format("{0}/{{userid}}/tokens", path)] = _ =>
            {
                return NullifyTokens(restClient, _.userid);
            };
        }

        protected class AuthRequest
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

        protected virtual dynamic WhoAmI(RestClient restClient)
        {
            var request = new RestRequest("whoami", Method.GET);
            CopyAuthorizationHeader(request);

            return Proxy(restClient, request);
        }

        protected virtual dynamic SafeRedirect(RestClient restClient, string response_type, string redirectUri, string clientId, string state, string scope, bool denyAccess)
        {
            var request = new RestRequest("saferedirect", Method.GET);
            CopyAuthorizationHeader(request);
            request.Parameters.Add(new Parameter { Type = ParameterType.QueryString, Name = "response_type", Value = string.IsNullOrEmpty(response_type) ? "code" : response_type });
            request.Parameters.Add(new Parameter { Type = ParameterType.QueryString, Name = "deny_access", Value = denyAccess });
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

            return Proxy(restClient, request);
        }

        protected virtual dynamic Auth(RestClient restClient, AuthRequest model, string clientId, bool detectGrantType)
        {
            var request = new RestRequest("auth", Method.POST);
            if (string.IsNullOrEmpty(model.client_id))
            {
                model.client_id = clientId;
            }
            if (string.IsNullOrEmpty(model.grant_type) && detectGrantType)
            {
                model.grant_type = DetectGrantType(model);
            }
            request.AddJsonBody(model);

            return Proxy(restClient, request);
        }

        protected virtual dynamic NullifyTokens(RestClient restClient, string userid)
        {
            var request = new RestRequest(string.Format("{0}/tokens", userid), Method.DELETE);
            CopyAuthorizationHeader(request);

            return Proxy(restClient, request);
        }

        protected virtual dynamic Proxy(RestClient restClient, RestRequest request)
        {
            var response = restClient.Execute(request);
            if (response.ErrorException == null && !string.IsNullOrEmpty(response.Content))
            {
                return Send((Nancy.HttpStatusCode)response.StatusCode, new System.Net.Mime.ContentType(response.ContentType).MediaType, response.Content);
            }
            else if (response.ErrorException == null)
            {
                return (Nancy.HttpStatusCode)response.StatusCode;
            }
            else
            {
                return Send(Nancy.HttpStatusCode.InternalServerError, new { reason = response.ErrorException.Message });
            }
        }

        protected virtual Nancy.Response Send(Nancy.HttpStatusCode status, string contentType, string content)
        {
            return new Nancy.Response
            {
                StatusCode = status,
                ContentType = new System.Net.Mime.ContentType(contentType).MediaType,
                Contents = res =>
                {
                    using (var writer = new System.IO.StreamWriter(res))
                    {
                        writer.Write(content);
                    }
                }
            };
        }

        protected virtual Nancy.Response Send(Nancy.HttpStatusCode status, dynamic content)
        {
            return Send(status, "application/json", Newtonsoft.Json.JsonConvert.SerializeObject(content));
        }

        protected virtual Nancy.Response Send(Nancy.HttpStatusCode status, string content)
        {
            return Send(status, "text/plain; charset=utf-8", content);
        }

        protected virtual void CopyAuthorizationHeader(RestRequest request)
        {
            Request.Headers
                .Where(h => h.Key.Equals("authorization", StringComparison.InvariantCultureIgnoreCase))
                .ToList()
                .ForEach(h => h.Value.ToList().ForEach(v => request.AddHeader("Authorization", v)));
        }

        protected virtual string DetectGrantType(AuthRequest model)
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
    }
}