# Guia de Implementação - Microsoft Entra ID em Projetos Legados .NET Framework

Este guia documenta o passo a passo para implementar autenticação SSO com Microsoft Entra ID (antigo Azure AD) em aplicações ASP.NET MVC legadas.

## Pré-requisitos

- **.NET Framework 4.6.2 ou superior** (obrigatório)
- Visual Studio 2017 ou superior
- Acesso ao portal do Microsoft Entra ID (Azure Portal)
- Aplicação ASP.NET MVC existente

---

## Padrão de Autenticação e Versão do Framework (.NET)

### Matriz de Compatibilidade e Requisitos

| Status | Versão do .NET Framework | Veredito |
|--------|--------------------------|---------|
| **Recomendado** | 4.7.2 ou 4.8 | Padrão ideal para segurança, conformidade e estabilidade. |
| **Mínimo Suportado** | 4.6.2 | Aceitável com restrições e necessidade de mitigação manual de vulnerabilidades. |
| **Não Suportado** | 4.6.1 ou inferior | Proibido. Risco alto de segurança e incompatibilidade com protocolos modernos. |

### Justificativa Técnica das Decisões

#### Por que versões abaixo da 4.6.2 não são recomendadas?

A utilização de versões anteriores à 4.6.2 (ex: 4.5, 4.5.2) inviabiliza o uso da biblioteca de autenticação moderna ([MSAL.NET](https://www.nuget.org/packages/microsoft.identity.client/)), forçando o uso de tecnologias obsoletas:

- **Fim do Suporte da ADAL**: Versões antigas dependeriam da Active Directory Authentication Library (ADAL), cujo suporte foi [encerrado pela Microsoft em junho de 2023](https://learn.microsoft.com/en-us/entra/identity-platform/msal-migration) (End of Life). O uso desta biblioteca em produção constitui uma não conformidade de segurança (High Risk Finding). [[1]](https://techcommunity.microsoft.com/blog/microsoft-entra-blog/update-your-applications-to-use-microsoft-authentication-library-and-microsoft-g/1257363)
- **Incompatibilidade de TLS**: O Microsoft Entra ID (Azure AD) [exige conexões via TLS 1.2](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-tls-enforcement). Versões antigas do framework não negociam este protocolo nativamente, exigindo intervenções manuais no código (`ServicePointManager`) que são propensas a falhas humanas e interrupções de serviço. [[2]](https://learn.microsoft.com/en-us/dotnet/framework/network-programming/tls)
- **Fim de Suporte do .NET**: As versões 4.5.2, 4.6 e 4.6.1 do .NET Framework [atingiram o fim do suporte em 26 de abril de 2022](https://devblogs.microsoft.com/dotnet/net-framework-4-5-2-4-6-4-6-1-will-reach-end-of-support-on-april-26-2022/), não recebendo mais correções de segurança.

#### Por que a versão 4.6.2 é o "Mínimo Suportado" (com ressalvas)?

A versão 4.6.2 é a [base mínima para executar a biblioteca atual `Microsoft.Identity.Client` (MSAL)](https://www.nuget.org/packages/microsoft.identity.client/). No entanto, ela apresenta desafios de manutenção:

- **Vulnerabilidades de Dependência**: O ecossistema de pacotes NuGet compatível com 4.6.2 frequentemente alerta para vulnerabilidades nas bibliotecas de tokens (`System.IdentityModel.Tokens.Jwt` série 5.x), como a [CVE-2024-21319](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21319) (Denial of Service, CVSS 6.8). A mitigação exige o forçamento manual de pacotes para versões mais recentes (série 6.x), aumentando a complexidade de gestão de dependências. [[3]](https://github.com/advisories/GHSA-59j7-ghrg-fj52)

#### Por que a versão 4.7.2+ é a Recomendada?

A atualização para o .NET Framework 4.7.2 ou 4.8 elimina dívidas técnicas críticas:

- **Suporte Nativo ao [.NET Standard 2.0](https://learn.microsoft.com/en-us/dotnet/standard/net-standard)**: Permite o uso transparente das versões mais seguras e recentes das bibliotecas de identidade e criptografia, sem conflitos de DLLs. O .NET Framework 4.7.2 é a [versão mínima recomendada pela Microsoft](https://learn.microsoft.com/en-us/dotnet/standard/net-standard#net-framework-compatibility-mode) para consumir bibliotecas .NET Standard 2.0 de forma confiável.
- **Criptografia Robusta**: O sistema operacional gerencia a negociação de protocolos de segurança (TLS 1.2/1.3) automaticamente, garantindo conformidade imediata com as políticas de segurança do Microsoft Entra ID. [[4]](https://learn.microsoft.com/en-us/dotnet/framework/network-programming/tls)

---

## Requisitos Específicos para .NET Framework 4.6.2

Ao utilizar o .NET Framework 4.6.2 como target, é necessário observar as seguintes restrições em relação às dependências:

### Versões dos Pacotes Microsoft.IdentityModel

Os pacotes `Microsoft.IdentityModel.*` na série **8.x** exigem .NET Framework 4.7.2 ou superior. Para o 4.6.2, é obrigatório utilizar a série **5.3.0**, que suporta `net461`:

| Pacote | Versão Compatível (4.6.2) | Versão Incompatível |
|--------|---------------------------|---------------------|
| `Microsoft.IdentityModel.Tokens` | 5.3.0 | 8.x (requer net472) |
| `Microsoft.IdentityModel.Logging` | 5.3.0 | 8.x (requer net472) |
| `Microsoft.IdentityModel.Protocols` | 5.3.0 | 8.x (requer net472) |
| `Microsoft.IdentityModel.Protocols.OpenIdConnect` | 5.3.0 | 8.x (requer net472) |
| `System.IdentityModel.Tokens.Jwt` | 5.3.0 | 8.x (requer net472) |

> **Atenção**: O pacote `Microsoft.IdentityModel.Abstractions` não existe na série 5.x e **não deve ser referenciado** ao usar o 4.6.2.

### Binding Redirects no Web.config

Os binding redirects devem apontar para a versão **5.3.0.0** (e não 8.15.0.0):

```xml
<dependentAssembly>
    <assemblyIdentity name="Microsoft.IdentityModel.Tokens" publicKeyToken="31bf3856ad364e35" culture="neutral"/>
    <bindingRedirect oldVersion="0.0.0.0-5.3.0.0" newVersion="5.3.0.0"/>
</dependentAssembly>
<dependentAssembly>
    <assemblyIdentity name="Microsoft.IdentityModel.Logging" publicKeyToken="31bf3856ad364e35" culture="neutral"/>
    <bindingRedirect oldVersion="0.0.0.0-5.3.0.0" newVersion="5.3.0.0"/>
</dependentAssembly>
```

### TLS 1.2 Obrigatório

No .NET Framework 4.6.2, o TLS 1.2 **não é o protocolo padrão**. É necessário forçá-lo explicitamente no `Startup.cs`:

```csharp
ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
```

> No .NET Framework 4.7+ o TLS 1.2 é negociado automaticamente pelo sistema operacional, tornando essa linha desnecessária (embora inofensiva).

### Vulnerabilidades Conhecidas

Os pacotes da série 5.3.0 possuem vulnerabilidades de severidade moderada reportadas pelo NuGet ([GHSA-59j7-ghrg-fj52](https://github.com/advisories/GHSA-59j7-ghrg-fj52) / [CVE-2024-21319](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21319)). Para ambientes de produção, considere:

1. Migrar para .NET Framework 4.7.2+ para utilizar pacotes da série 6.x/8.x
2. Avaliar o risco da vulnerabilidade no contexto da sua aplicação
3. Aplicar controles compensatórios de segurança na camada de infraestrutura

---

## Requisitos para .NET Framework 4.7.2+

Ao utilizar o .NET Framework 4.7.2 ou 4.8 como target, a integração com o Microsoft Entra ID é significativamente simplificada devido ao suporte nativo ao [.NET Standard 2.0](https://learn.microsoft.com/en-us/dotnet/standard/net-standard) e à negociação automática de [TLS 1.2](https://learn.microsoft.com/en-us/dotnet/framework/network-programming/tls).

### Versões dos Pacotes Microsoft.IdentityModel

Com o .NET Framework 4.7.2+, é possível utilizar a série **8.x** dos pacotes `Microsoft.IdentityModel.*`, que é a versão mais recente e segura:

| Pacote | Versão Recomendada (4.7.2+) | Observação |
|--------|-----------------------------|------------|
| `Microsoft.IdentityModel.Tokens` | 8.x (ex: 8.15.0) | Suporte completo ao net472 |
| `Microsoft.IdentityModel.Logging` | 8.x (ex: 8.15.0) | Suporte completo ao net472 |
| `Microsoft.IdentityModel.Protocols` | 8.x (ex: 8.15.0) | Suporte completo ao net472 |
| `Microsoft.IdentityModel.Protocols.OpenIdConnect` | 8.x (ex: 8.15.0) | Suporte completo ao net472 |
| `Microsoft.IdentityModel.Abstractions` | 8.x (ex: 8.15.0) | **Disponível apenas na série 8.x** |
| `System.IdentityModel.Tokens.Jwt` | 8.x (ex: 8.15.0) | Suporte completo ao net472 |

> **Nota**: O pacote `Microsoft.IdentityModel.Abstractions` **é necessário** na série 8.x e será instalado automaticamente como dependência transitiva.

### Binding Redirects no Web.config

Os binding redirects devem apontar para a versão **8.x** instalada (ex: 8.15.0.0):

```xml
<dependentAssembly>
    <assemblyIdentity name="Microsoft.IdentityModel.Tokens" publicKeyToken="31bf3856ad364e35" culture="neutral"/>
    <bindingRedirect oldVersion="0.0.0.0-8.15.0.0" newVersion="8.15.0.0"/>
</dependentAssembly>
<dependentAssembly>
    <assemblyIdentity name="Microsoft.IdentityModel.Logging" publicKeyToken="31bf3856ad364e35" culture="neutral"/>
    <bindingRedirect oldVersion="0.0.0.0-8.15.0.0" newVersion="8.15.0.0"/>
</dependentAssembly>
<dependentAssembly>
    <assemblyIdentity name="Microsoft.IdentityModel.Abstractions" publicKeyToken="31bf3856ad364e35" culture="neutral"/>
    <bindingRedirect oldVersion="0.0.0.0-8.15.0.0" newVersion="8.15.0.0"/>
</dependentAssembly>
```

> **Dica**: Ajuste os valores `8.15.0.0` para a versão exata instalada via NuGet no seu projeto.

### TLS 1.2 Automático

No .NET Framework 4.7+, o TLS 1.2 é [negociado automaticamente pelo sistema operacional](https://learn.microsoft.com/en-us/dotnet/framework/network-programming/tls). Não é necessário configurar `ServicePointManager.SecurityProtocol` manualmente:

```csharp
// NÃO necessário no 4.7.2+ (mas inofensivo se presente)
// ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
```

O `Startup.cs` pode omitir essa configuração, simplificando o código:

```csharp
public void Configuration(IAppBuilder app)
{
    // TLS 1.2 é negociado automaticamente pelo OS no 4.7.2+
    ConfigureAuth(app);
}
```

### Segurança dos Pacotes

A série 8.x dos pacotes `Microsoft.IdentityModel.*` resolve as vulnerabilidades conhecidas da série 5.x ([CVE-2024-21319](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21319)), eliminando a necessidade de mitigações manuais. Além disso, recebe atualizações de segurança ativas da Microsoft.

### Vantagens em Relação ao 4.6.2

| Aspecto | .NET Framework 4.6.2 | .NET Framework 4.7.2+ |
|---------|----------------------|----------------------|
| Pacotes IdentityModel | Série 5.3.0 (vulnerável) | Série 8.x (atual e segura) |
| TLS 1.2 | Configuração manual obrigatória | Automático pelo OS |
| .NET Standard 2.0 | Suporte parcial com limitações | Suporte nativo completo |
| `IdentityModel.Abstractions` | Não disponível | Disponível e necessário |
| Manutenção de dependências | Complexa (conflitos de DLLs) | Simplificada |

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
    <add key="owin:AppStartup" value="SeuNamespace.Startup" />
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
                    new AuthenticationProperties { RedirectUri = "/", IsPersistent = true },
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

Adicione a verificação de autenticação no header. Quando autenticado, exibe o nome do usuário e o botão de logout:

```html
@if (Request.IsAuthenticated)
{
    <nav class="user-nav">
        <span class="user-name">@User.Identity.Name</span>
        <a href="@Url.Action("SignOut", "Account")" class="btn-logout">Sair</a>
    </nav>
}
```

> **Nota**: O link de login ("Entrar") pode ser posicionado na view principal (ex: `Index.cshtml`) em vez do layout, conforme a necessidade da aplicação.

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

### Documentação Geral

- [Documentação Microsoft Entra ID](https://learn.microsoft.com/en-us/entra/identity/)
- [OWIN OpenID Connect Middleware](https://learn.microsoft.com/en-us/aspnet/aspnet/overview/owin-and-katana/)
- [App Registration no Azure](https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app)

### Segurança e Compatibilidade de Versões

- **[1]** [Migração de ADAL para MSAL - Anúncio oficial do fim do suporte da ADAL](https://techcommunity.microsoft.com/blog/microsoft-entra-blog/update-your-applications-to-use-microsoft-authentication-library-and-microsoft-g/1257363) — Microsoft Entra Blog
- **[1]** [Guia de Migração ADAL → MSAL](https://learn.microsoft.com/en-us/entra/identity-platform/msal-migration) — Microsoft Learn
- **[2]** [Transport Layer Security (TLS) best practices with .NET Framework](https://learn.microsoft.com/en-us/dotnet/framework/network-programming/tls) — Microsoft Learn
- **[2]** [TLS 1.2 enforcement for Microsoft Entra Connect](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-tls-enforcement) — Microsoft Learn
- **[3]** [CVE-2024-21319: Microsoft Identity Denial of Service Vulnerability](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21319) — MSRC (CVSS 6.8)
- **[3]** [GHSA-59j7-ghrg-fj52: .NET Denial of Service Vulnerability](https://github.com/advisories/GHSA-59j7-ghrg-fj52) — GitHub Advisory Database
- **[4]** [.NET Standard - Tabela de compatibilidade](https://learn.microsoft.com/en-us/dotnet/standard/net-standard) — Microsoft Learn
- [Microsoft.Identity.Client (MSAL.NET) - NuGet](https://www.nuget.org/packages/microsoft.identity.client/) — Frameworks suportados: net462, net472, netstandard2.0, net8.0
- [.NET Framework 4.5.2, 4.6, 4.6.1 End of Support (Abril 2022)](https://devblogs.microsoft.com/dotnet/net-framework-4-5-2-4-6-4-6-1-will-reach-end-of-support-on-april-26-2022/) — .NET Blog
- [Política oficial de suporte do .NET Framework](https://dotnet.microsoft.com/en-us/platform/support/policy/dotnet-framework) — Microsoft