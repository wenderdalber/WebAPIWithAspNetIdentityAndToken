using Microsoft.Owin;
using Microsoft.Owin.Security.OAuth;
using Owin;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using WebAPILoginWithAspNetIdentity.Models;

namespace WebAPILoginWithAspNetIdentity
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            app.CreatePerOwinContext(IdentityContext.Create);
            app.CreatePerOwinContext<IdentityConfig.ApplicationUserManager>(IdentityConfig.ApplicationUserManager.Create);
            app.CreatePerOwinContext<IdentityConfig.ApplicationSignInManager>(IdentityConfig.ApplicationSignInManager.Create);

            OAuthAuthorizationServerOptions OAuthServerOptions = new OAuthAuthorizationServerOptions()
            {
                AllowInsecureHttp = true,
                TokenEndpointPath = new PathString("/api/security/token"),
                AccessTokenExpireTimeSpan = TimeSpan.FromHours(2),
                Provider = new AuthorizationServerProvider()
            };

            app.UseOAuthAuthorizationServer(OAuthServerOptions);
            app.UseOAuthBearerAuthentication(new OAuthBearerAuthenticationOptions());
        }

        //public void ConfigureOAuth(IAppBuilder app)
        //{

        //}
    }
}