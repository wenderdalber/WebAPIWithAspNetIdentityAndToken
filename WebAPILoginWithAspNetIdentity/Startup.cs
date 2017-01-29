using Owin;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using WebAPILoginWithAspNetIdentity.Model;

namespace WebAPILoginWithAspNetIdentity
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            app.CreatePerOwinContext(IdentityContext.Create);
            app.CreatePerOwinContext<IdentityConfig.ApplicationUserManager>(IdentityConfig.ApplicationUserManager.Create);
            app.CreatePerOwinContext<IdentityConfig.ApplicationSignInManager>(IdentityConfig.ApplicationSignInManager.Create);
        }
    }
}