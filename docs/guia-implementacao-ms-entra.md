# Guia de Implementação - Microsoft Entra ID em Projetos Legados .NET Framework

Este guia documenta o passo a passo para implementar autenticação SSO com Microsoft Entra ID (antigo Azure AD) em aplicações ASP.NET MVC legadas.

## Pré-requisitos

- **.NET Framework 4.6.2 ou superior** (obrigatório)
- Visual Studio 2017 ou superior
- Acesso ao portal do Microsoft Entra ID (Azure Portal)
- Aplicação ASP.NET MVC existente

---

## Passo 1: Registrar a Aplicação no Microsoft Entra ID

### 1.1 Criar o App Registration

1. Acesse o [Portal Azure](https://portal.azure.com)
2. Navegue até **Microsoft Entra ID** → **App registrations** → **New registration**
3. Preencha:
   - **Name**: Nome da sua aplicação
   - **Supported account types**: Escolha conforme necessidade (geralmente "Single tenant")
   - **Redirect URI**: Selecione "Web" e insira `https://localhost:44300/signin-oidc`

### 1.2 Copiar as Credenciais

Após criar, anote:
- **Application (client) ID** → será o `ida:ClientId`
- **Directory (tenant) ID** → será o `ida:TenantId`

### 1.3 Criar o Client Secret

1. Vá em **Certificates & secrets** → **New client secret**
2. Defina uma descrição e expiração
3. **Copie o valor imediatamente** (não será mostrado novamente) → será o `ida:ClientSecret`

### 1.4 Configurar a Autenticação

1. Vá em **Authentication**
2. Em **Redirect URIs**, adicione:
   - `https://localhost:44300/signin-oidc` (desenvolvimento)
   - `https://seu-dominio.com/signin-oidc` (produção)
3. Em **Front-channel logout URL**, adicione:
   - `https://localhost:44300/signout-oidc`
4. Marque **ID tokens** em "Implicit grant and hybrid flows"

---

## Passo 2: Instalar os Pacotes NuGet

Execute no Package Manager Console:

```powershell
Install-Package Microsoft.Owin.Host.SystemWeb
Install-Package Microsoft.Owin.Security.Cookies
Install-Package Microsoft.Owin.Security.OpenIdConnect
Install-Package Microsoft.IdentityModel.Protocols.OpenIdConnect
```

Ou via .NET CLI:

```bash
dotnet add package Microsoft.Owin.Host.SystemWeb
dotnet add package Microsoft.Owin.Security.Cookies
dotnet add package Microsoft.Owin.Security.OpenIdConnect
dotnet add package Microsoft.IdentityModel.Protocols.OpenIdConnect
```

---

## Passo 3: Configurar o Web.config

Adicione as seguintes chaves na seção `<appSettings>`:

```xml
<appSettings>
    <!-- Configurações existentes... -->

    <!-- Microsoft Entra ID Configuration -->
    <add key="ida:TenantId" value="SEU_TENANT_ID" />
    <add key="ida:ClientId" value="SEU_CLIENT_ID" />
    <add key="ida:ClientSecret" value="SEU_CLIENT_SECRET" />
    <add key="ida:RedirectUri" value="https://localhost:44300/signin-oidc" />
    <add key="ida:PostLogoutRedirectUri" value="https://localhost:44300/" />
</appSettings>
```

> **Segurança**: Em produção, use Azure Key Vault ou variáveis de ambiente para armazenar o ClientSecret.

---

## Passo 4: Criar a Classe Startup.cs

Crie o arquivo `Startup.cs` na raiz do projeto:

```csharp
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;
using System;
using System.Configuration;
using System.Net;
using System.Threading.Tasks;

[assembly: OwinStartup(typeof(SeuNamespace.Startup))]

namespace SeuNamespace
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
            // Força TLS 1.2 (obrigatório para Microsoft Entra ID)
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

            ConfigureAuth(app);
        }

        private void ConfigureAuth(IAppBuilder app)
        {
            // Configura o cookie como método padrão de autenticação
            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);

            // Middleware de Cookie - mantém a sessão do usuário
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = CookieAuthenticationDefaults.AuthenticationType,
                CookieSecure = CookieSecureOption.Always,
                ExpireTimeSpan = TimeSpan.FromHours(1),
                SlidingExpiration = true
            });

            // Middleware OpenID Connect - comunicação com Entra ID
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
```

---

## Passo 5: Criar o AccountController

Crie `Controllers/AccountController.cs`:

```csharp
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using System.Web;
using System.Web.Mvc;

namespace SeuNamespace.Controllers
{
    public class AccountController : Controller
    {
        public void SignIn()
        {
            if (!Request.IsAuthenticated)
            {
                HttpContext.GetOwinContext().Authentication.Challenge(
                    new AuthenticationProperties { RedirectUri = "/" },
                    OpenIdConnectAuthenticationDefaults.AuthenticationType);
            }
        }

        public void SignOut()
        {
            HttpContext.GetOwinContext().Authentication.SignOut(
                OpenIdConnectAuthenticationDefaults.AuthenticationType,
                CookieAuthenticationDefaults.AuthenticationType);
        }
    }
}
```

---

## Passo 6: Implementar na Interface (Views)

### 6.1 No Layout (_Layout.cshtml)

Adicione a verificação de autenticação:

```html
@if (Request.IsAuthenticated)
{
    <span>@User.Identity.Name</span>
    <a href="@Url.Action("SignOut", "Account")">Sair</a>
}
else
{
    <a href="@Url.Action("SignIn", "Account")">Entrar</a>
}
```

### 6.2 Exibir Claims do Usuário (opcional)

```html
@using System.Security.Claims

@if (Request.IsAuthenticated)
{
    var claimsIdentity = User.Identity as ClaimsIdentity;

    <table>
        @foreach (var claim in claimsIdentity.Claims)
        {
            <tr>
                <td>@claim.Type.Split('/').Last()</td>
                <td>@claim.Value</td>
            </tr>
        }
    </table>
}
```

---

## Passo 7: Proteger Rotas (Opcional)

### 7.1 Proteger um Controller inteiro

```csharp
[Authorize]
public class AdminController : Controller
{
    // Todas as actions requerem autenticação
}
```

### 7.2 Proteger uma Action específica

```csharp
public class HomeController : Controller
{
    public ActionResult Index()
    {
        return View(); // Pública
    }

    [Authorize]
    public ActionResult Dashboard()
    {
        return View(); // Requer autenticação
    }
}
```

### 7.3 Proteger toda a aplicação (Global)

Em `App_Start/FilterConfig.cs`:

```csharp
public static void RegisterGlobalFilters(GlobalFilterCollection filters)
{
    filters.Add(new HandleErrorAttribute());
    filters.Add(new AuthorizeAttribute()); // Adicione esta linha
}
```

---

## Resumo da Estrutura de Arquivos

```
/SeuProjeto
├── Startup.cs                          ← Configuração OWIN/Entra
├── Web.config                          ← Credenciais (ida:*)
├── Controllers/
│   └── AccountController.cs            ← SignIn/SignOut
└── Views/
    └── Shared/
        └── _Layout.cshtml              ← UI de login/logout
```

---

## Troubleshooting

### Erro: "IDX20803: Unable to obtain configuration"
- Verifique se TLS 1.2 está habilitado
- Confirme que o TenantId está correto

### Erro: "AADSTS50011: Reply URL mismatch"
- A RedirectUri no código deve corresponder exatamente à configurada no App Registration

### Erro: "AADSTS7000218: Invalid client secret"
- O ClientSecret expirou ou está incorreto
- Gere um novo secret no portal

### Cookie não persiste após login
- Verifique se a aplicação está rodando em HTTPS
- Confirme que `CookieSecure = CookieSecureOption.Always` está configurado

---

## Referências

- [Documentação Microsoft Entra ID](https://learn.microsoft.com/en-us/entra/identity/)
- [OWIN OpenID Connect Middleware](https://learn.microsoft.com/en-us/aspnet/aspnet/overview/owin-and-katana/)
- [App Registration no Azure](https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app)
