using System.Web.Http;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using WebAPILoginWithAspNetIdentity.Model;
using static WebAPILoginWithAspNetIdentity.Model.IdentityContext;
using System.Net.Http;
using System.Web;
using System.Linq;

namespace WebAPILoginWithAspNetIdentity.Controllers
{
    public class ValuesController : ApiController
    {
        // POST api/values
        [HttpPost]
        [Route("api/Users/Register")]
        public string Register(string username, string email, string password)
        {
            var manager = HttpContext.Current.GetOwinContext().GetUserManager<IdentityConfig.ApplicationUserManager>();
            var user = new ApplicationUser() { UserName = username, Email = email };

            //criando o usuário pelo método do Ideentity
            IdentityResult result = manager.Create(user, password);

            //verificando o resultado do create foi com sucesso
            if (result.Succeeded)
            {
                return "Usuário cadastrado com sucesso!";
            }
            return "Erro ao cadastrar usuário, tente novamente em alguns instantes";
        }

        [HttpPost]
        [Route("api/Users/Login")]
        public string Login(string username, string password)
        {
            // Validando usuário e password
            var manager = HttpContext.Current.GetOwinContext().GetUserManager<IdentityConfig.ApplicationUserManager>();
            var signinManager =
                HttpContext.Current.GetOwinContext().GetUserManager<IdentityConfig.ApplicationSignInManager>();

            //buscando o usuário no banco, se e-mail ou nome
            //estiverem certo continua o login
            var user =
                manager.Users.FirstOrDefault(
                    x => x.UserName == username || x.Email == username);

            //Se usuário for diferente de null valida a senha
            if (user != null)
            {
                //realiza o login com o usuario e senha digitados com
                //o método SigninManager do Identity, terceiro item é
                //o remember, marcado como false por padrão
                var result = signinManager.PasswordSignIn(user.UserName, password, false,
                    shouldLockout: false);
                switch (result)
                {
                    case SignInStatus.Success:
                        return "Olá " + user.UserName + " você está logado!";
                }
            }
            return "Usuário ou senha inválidos!";
        }

        [HttpPost]
        [Route("api/Users/Logout")]
        public string Logout()
        {
            HttpContext.Current.GetOwinContext().Authentication.SignOut();
            return "Você saiu do sistema!";
        }
    }
}
