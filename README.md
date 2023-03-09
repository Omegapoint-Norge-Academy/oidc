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
There needs to be two authentication scheme.
One for cookie, and one for OpenID Connect.
These name of these schemes are embedded in framework constants:
``` csharp
CookieAuthenticationDefaults.AuthenticationScheme
OpenIdConnectDefaults.AuthenticationScheme
```