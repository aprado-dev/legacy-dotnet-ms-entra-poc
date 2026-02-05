using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;
using System;
using System.Configuration;
using System.Net;
using System.Threading.Tasks;

[assembly: OwinStartup(typeof(MSEntraPOC.Startup))]

namespace MSEntraPOC
{
    public class Startup
    {
        private static string clientId = ConfigurationManager.AppSettings["ida:ClientId"];
        private static string tenantId = ConfigurationManager.AppSettings["ida:TenantId"];
        private static string redirectUri = ConfigurationManager.AppSettings["ida:RedirectUri"];
        private static string postLogoutRedirectUri = ConfigurationManager.AppSettings["ida:PostLogoutRedirectUri"];
        private static string authority = $"https://login.microsoftonline.com/{tenantId}/v2.0";

        public void Configuration(IAppBuilder app)
        {
            // Força TLS 1.2 (necessário para Microsoft Entra ID)
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

            ConfigureAuth(app);
        }

        private void ConfigureAuth(IAppBuilder app)
        {
            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);

            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = CookieAuthenticationDefaults.AuthenticationType,
                CookieSecure = CookieSecureOption.Always,
                ExpireTimeSpan = TimeSpan.FromHours(1),
                SlidingExpiration = true
            });

            app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions
            {
                ClientId = clientId,
                Authority = authority,
                RedirectUri = redirectUri,
                PostLogoutRedirectUri = postLogoutRedirectUri,
                Scope = "openid profile email",
                ResponseType = "code id_token",
                TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidIssuer = $"https://login.microsoftonline.com/{tenantId}/v2.0"
                },
                Notifications = new OpenIdConnectAuthenticationNotifications
                {
                    AuthenticationFailed = context =>
                    {
                        context.HandleResponse();
                        context.Response.Redirect("/Home/Error?message=" + context.Exception.Message);
                        return Task.FromResult(0);
                    }
                }
            });
        }
    }
}
