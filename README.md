# oidc
Course material for OIDC

# Workshop guide
## Dependencies
Install the following dependencies using Nuget
- IdentityModel
- Microsoft.AspNetCore.Authentication.OpenIdConnect

## Bootstrapping
### Middleware
Add authentication and authorization middleware to program file.
It should be added after `UseRouting()` but before `MapControllers()`.
``` csharp
app.UseAuthentication();
app.UseAuthorization();
```

Authentication Middleware `UseAuthentication()` attempts to authenticate the user before they're allowed access to secure resources.
Authorization Middleware `UseAuthorization()` authorizes a user to access secure resources.

### Add Authorization
There needs to be two authentication schemes, one for cookie, and one for OpenID Connect.
These name of these schemes are embedded in framework constants:
``` csharp
CookieAuthenticationDefaults.AuthenticationScheme
OpenIdConnectDefaults.AuthenticationScheme
```
These will be configured separately by adding them us below
``` csharp
builder.Services
    .AddAuthentication()
    .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
    {
    })
    .AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
    {
    });
```
Add this to `Program.cs` just after var `builder = WebApplication.CreateBuilder(args);`

Both these schemes have to be configured. Lets focus on the cookie first.
#### Cookie options
This cookie defines the session between the frontend and the BFF.

These are the options that needs to be configured:
- [Cookie.HttpOnly](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#httponly-attribute)
- [Cookie.SecurePolicy](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#secure-attribute)
- [Cookie.SameSite](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#samesite-attribute)

To manage the lifetime of the cookie configure these properties:
- ExpireTimeSpan
- SlidingExpiration

Set the expire to 60 minutes, and sliding to true.

The SlidingExpiration is set to true to instruct the handler to re-issue a new cookie with a new expiration time any time it processes a request which is more than halfway through the expiration window.

A session cookie should always be considered essential to the application.
To skip cookie consent, configure `IsEssential` to `true`.

Lastly add code to deliver 403 forbidden insted of redirecting to the login page when a resource is denied.
``` csharp
options.Events.OnRedirectToAccessDenied = context =>
{
    context.Response.StatusCode = StatusCodes.Status403Forbidden;
    return Task.CompletedTask;
};
```

When all this is done, the code should look like this:
<details>
<summary>Spoiler</summary>
<p>

``` csharp
.AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
{
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.Cookie.IsEssential = true;
    options.ExpireTimeSpan = TimeSpan.FromMinutes(60);
    options.SlidingExpiration = true;
    
    options.Events.OnRedirectToAccessDenied = context =>
    {
        context.Response.StatusCode = StatusCodes.Status403Forbidden;
        return Task.CompletedTask;
    };
})
```
</p>
</details>

#### OpenID connect options

This is the configuration that allows us to login using the identity provider (IDP).

Add options for using Authorization code flow with PKCE:
``` csharp
options.ResponseType = OpenIdConnectResponseType.Code;
options.UsePkce = true;
```

Add additional options
``` csharp
options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
options.RequireHttpsMetadata = true;
options.SaveTokens = true;
```

The `SignInScheme` will make sure that the result of the sign in will be saved to the cookie.
Setting `RequireHttpsMetadata` to true will make sure https is used when fetching metadata from the IDP.
`SaveTokens` make sure tokens are saved to the cookie for later use.

Add IDP configuration (client secret will be handed out separately)
``` csharp
options.Authority = "https://dev-my7g8x3rrwfzi3lh.eu.auth0.com";
options.ClientId = "BbSr54nCG1OEl0k9GZi45qeFXnnJttpC";
options.ClientSecret = "";
```

Make sure to configure what scopes to request:
``` csharp
options.Scope.Clear();
options.Scope.Add("openid");
options.Scope.Add("profile");
```

The `openid` scope is added to instruct that we are using OpenID connect and not pure OAuth2.0.
The `profile` scope will instruct the IDP to return claims as
`name`, `family_name`, `given_name`, `middle_name`, `nickname`, `picture`, and `updated_at` if available.
In essence the `profile` scope lets us get basic user profile info.

Most identity providers (IDPs) have there own quirks.
Auth0 have a sign out endpoint that does not conform to standards.
To handle this, add this code to the options:
``` csharp
options.SignedOutCallbackPath = "/";
options.Events.OnRedirectToIdentityProviderForSignOut = context =>
{
    var logoutUri = $"{context.Options.Authority}/v2/logout?client_id={context.Options.ClientId}";
    var postLogoutUri = context.ProtocolMessage.PostLogoutRedirectUri;
    if (!string.IsNullOrEmpty(postLogoutUri))
    {
        logoutUri += $"&returnTo={HttpUtility.UrlEncode(postLogoutUri)}";
    }

    context.ProtocolMessage.IssuerAddress = logoutUri;

    return Task.CompletedTask;
};
```
This code builds the sign out request uri and configures the sign out callback.

When all this is added, the code should look like this:
<details>
<summary>Spoiler</summary>
<p>

``` csharp
.AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
{
    options.ResponseType = OpenIdConnectResponseType.Code;
    options.UsePkce = true;

    options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.RequireHttpsMetadata = true;
    options.SaveTokens = true;

    options.Authority = "https://dev-my7g8x3rrwfzi3lh.eu.auth0.com";
    options.ClientId = "BbSr54nCG1OEl0k9GZi45qeFXnnJttpC";
    options.ClientSecret = "";

    options.Scope.Clear();
    options.Scope.Add("openid");
    options.Scope.Add("profile");

    // Auth0 specific implementation
    options.SignedOutCallbackPath = "/";
    options.Events.OnRedirectToIdentityProviderForSignOut = context =>
    {
        var logoutUri = $"{context.Options.Authority}/v2/logout?client_id={context.Options.ClientId}";
        var postLogoutUri = context.ProtocolMessage.PostLogoutRedirectUri;
        if (!string.IsNullOrEmpty(postLogoutUri))
        {
            logoutUri += $"&returnTo={HttpUtility.UrlEncode(postLogoutUri)}";
        }

        context.ProtocolMessage.IssuerAddress = logoutUri;

        return Task.CompletedTask;
    };
})
```
</p>
</details>

#### Default schemas
We need to tell .NET that our default scheme is cookie, and that our challenge scheme is openid.
To du this, add some options to `AddAuthentication()`
``` csharp
.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
})
```