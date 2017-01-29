using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security.OAuth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using System.Web;

namespace WebAPILoginWithAspNetIdentity.Models
{
    public class AuthorizationServerProvider : OAuthAuthorizationServerProvider
    {
        //apenas recebe um contexto e valida se o token é válido ou não, evitando que
        //haja uma verificação no banco a cada requisição
        public override async Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            context.Validated();
        }

        //Método que realiza a autenticação
        public override async Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {
            //Método vem de um lugar e retorna, o * permite que haja troca de dados entre
            //servidores diferentes
            context.OwinContext.Response.Headers.Add("Access-Control-Allow-Origin", new[] { "*" });

            try
            {
                //área para consultar os dados que chegaram no banco, ele recebe um username e um password
                var username = context.UserName;
                var password = context.Password;

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

                    //seta uma identidade no aspnet e recebera os Claims, que serão nomeados
                    //nesse exemplo iremos apenas criar uma claim para o username, mas podemos
                    //criar para qualquer dado do usuário
                    var identity = new ClaimsIdentity(context.Options.AuthenticationType);

                    identity.AddClaim(new Claim(ClaimTypes.Name, username));

                    //criação de uma role, para validação de teste
                    var roles = new List<string>();
                    roles.Add("User");

                    foreach (var role in roles)
                    {
                        identity.AddClaim(new Claim(ClaimTypes.Role, role));
                    }

                    //Manager da conexão, o usuário em si que recebe o usuário e as roles
                    GenericPrincipal principal = new GenericPrincipal(identity, roles.ToArray());
                    //Sem esse Thread não se consegue recuperar os dados no controle
                    Thread.CurrentPrincipal = principal;

                    switch (result)
                    {
                        case SignInStatus.Success:
                            //Valida a identidade
                            context.Validated(identity);
                            break;
                    }
                }
                else
                {
                    context.SetError("invalid_grant", "Usuário ou senha inválidos");
                    return;
                }
            }
            catch
            {
                //Caso alguma coisa dê errada dispara um erro
                context.SetError("invalid_grant", "Falha ao autenticar");
            }
        }
    }
}