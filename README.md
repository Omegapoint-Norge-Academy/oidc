- [Intro](#intro)
    * [Getting started](#getting-started)
    * [Architecture](#architecture)
- [Workshop guide part 1 - Login and Logout](#workshop-guide-part-1---login-and-logout)
    * [Dependencies](#dependencies)
    * [Bootstrapping](#bootstrapping)
        + [Middleware](#middleware)
        + [Add Authentication](#add-authentication)
            - [Cookie options](#cookie-options)
            - [OpenID connect options](#openid-connect-options)
            - [Default schemas](#default-schemas)
        + [Add Authorization](#add-authorization)
    * [Account controller](#account-controller)
    * [Login and logout button](#login-and-logout-button)
    * [Part 1 milestone: Test login](#part-1-milestone-test-login)
- [Workshop guide part 2 - User context](#workshop-guide-part-2---user-context)
    * [User controller](#user-controller)
    * [Authentication state in frontend](#authentication-state-in-frontend)
    * [Login and logout button](#login-and-logout-button-1)
    * [Part 2 milestone: Test user context](#part-2-milestone-test-user-context)
- [Workshop guide part 3 - Accessing remote API](#workshop-guide-part-3---accessing-remote-api)
    * [Bootstrapping](#bootstrapping-1)
    * [Exchanging cookie for access token](#exchanging-cookie-for-access-token)
    * [Part 3 milestone: Test API access](#part-3-milestone-test-api-access)
- [Workshop guide part 4 - Refreshing the token](#workshop-guide-part-4---refreshing-the-token)
    * [Dependencies](#dependencies-1)
    * [Bootstrapping](#bootstrapping-2)
    * [Trigger refresh](#trigger-refresh)
    * [Part 4 milestone: Test token refresh](#part-4-milestone-test-token-refresh)
- [Workshop guide done](#workshop-guide-done)
- [Appendix](#appendix)
    * [Debugging .NET with Fiddler](#debugging-net-with-fiddler)

# Intro
This repo contains code and documentation for the OAuth2 and OpenID Connect.
The course focuses on best practices, and the BFF pattern.

The workshop is divided into four parts. Part one and two will take more time to complete than part three and four.

## Getting started
Clone/fork the repo and open the template in your IDE of choice [0-start-template](0-start-template)

## Architecture
The application has a same-site hosting setup. This means that the backend and frontend is hosted as the same site.
To account for this in development a SPA-proxy is added

![alt text](Resources/bff_pattern.png?raw=true)

# Workshop guide part 1 - Login and Logout
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

### Add Authentication
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

Lastly add code to deliver 403 forbidden instead of redirecting to the login page when a resource is denied.
``` csharp
options.Events.OnRedirectToAccessDenied = context =>
{
    context.Response.StatusCode = StatusCodes.Status403Forbidden;
    return Task.CompletedTask;
};
```

When all this is done, the code should look like this:
<details>
<summary><b>Spoiler (Full code)</b></summary>
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

We also want to make sure that redirect to the identity provider is not done when calling the API, or the user info endpoint
The framework will try to redirect to the identity provider when the API responds with Unauthorized.
We can modify this behaviour by adding intercepting the `OnRedirectToIdentityProvider` event and setting Unauthorized as the response.

``` csharp
options.Events.OnRedirectToIdentityProvider = context =>
{
    if (context.Request.Path.StartsWithSegments("/api") ||
        context.Request.Path.StartsWithSegments("/client/user"))
    {
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        context.HandleResponse();
    }

    return Task.CompletedTask;
};
```

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
<summary><b>Spoiler (Full code)</b></summary>
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

    options.Events.OnRedirectToIdentityProvider = context =>
    {
        if (context.Request.Path.StartsWithSegments("/api") ||
            context.Request.Path.StartsWithSegments("/client/user"))
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            context.HandleResponse();
        }
    
        return Task.CompletedTask;
    };

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
To do this, add some options to `AddAuthentication()`
``` csharp
.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
})
```

### Add Authorization
We need to add some kind of policy for our users.
Lets add authorization `AddAuthorization()` and create a simple policy.
The policy should only require a user to be authenticated.
Hint: use the `AuthorizationPolicyBuilder()`.

Make sure the policy is configured as default policy and fallback policy

The code should look something like this:
<details>
<summary><b>Spoiler (Full code)</b></summary>
<p>

``` csharp
builder.Services.AddAuthorization(options =>
{
    var defaultPolicy = new AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .Build();
    
    options.AddPolicy("AuthenticatedUser", defaultPolicy);
    options.DefaultPolicy = defaultPolicy;
    options.FallbackPolicy = defaultPolicy;
});
```
</p>
</details>

Also add the policy to all controllers and the reverse proxy by adding `RequireAuthorization()` to the middlewares.
Make sure that the policy names id the same as used in `AddPolicy()` earlier.
``` csharp
app.MapControllers().RequireAuthorization("AuthenticatedUser");
app.MapReverseProxy().RequireAuthorization("AuthenticatedUser");
```

When this is added, you dont need to add the authorize attribute to all controllers.

## Account controller
The account controller should handle login and logout.

Create a controller called `AccountController`,
and add two endpoints:

**client/account/login:** This endpoint should be a http get, and it should accept a `returnUrl` as a query parameter.
It should return a `Challenge()` where the `returnUrl` is passed inn by `AuthenticationProperties`. If the `returnUrl` is null, then it should be set to "/".
The `returnUrl` should be validated to be relative. This will protect against open redirector attacks. Use `Url.IsLocalUrl` to check if the `returnUrl` is valid.
See https://learn.microsoft.com/en-us/aspnet/core/security/preventing-open-redirects?view=aspnetcore-7.0 for more info.
The endpoint should be accessible for anonymous users.

**client/account/logout:** This endpoint should be a http get, and accept no parameters.
It should do a `HttpContext.SignOutAsync()` on both the cookie scheme, and the openid scheme.
When signing out of the cookie scheme a redirect uri to the home page of the app should be configured.

<details>
<summary><b>Spoiler (Full code)</b></summary>
<p>

``` csharp
[ApiController]
[Route("client/[controller]")]
public class AccountController : ControllerBase
{
    [AllowAnonymous]
    [HttpGet("Login")]
    public ActionResult Login([FromQuery] string? returnUrl)
    {
        if (string.IsNullOrEmpty(returnUrl) || !Url.IsLocalUrl(returnUrl))
        {
            returnUrl = "/";
        }
        var properties = new AuthenticationProperties { RedirectUri = $"https://localhost:44469{returnUrl}" };
        
        return Challenge(properties);
    }

    [Authorize]
    [HttpGet("Logout")]
    public async Task Logout()
    {
        await HttpContext.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme, new AuthenticationProperties
        {
            RedirectUri = "https://localhost:44469/",
        });
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    }
}
```
</p>
</details>

## Login and logout button
Now that we have an login and logout endpoints, we can add a login button and a logout button.
We do not yet have any authentication state in the frontend, so we dont know what button to render yet.
So for now we will render both buttons no matter what.
Add the buttons after the NavbarBrand in `NavMenu.js`.
It is very important that the login/logout endpoints are navigated to. These endpoints will return a html page.
The easiest solution is to use the `<a>` element.

Example component below.

<details>
<summary><b>Authentication.js</b></summary>
<p>

``` js
import React from "react";
import { useLocation } from "react-router-dom";

export function Authentication() {
    const location = useLocation();

    return <div>
        <a href={`client/account/login?returnUrl=${location.pathname}`}>click here to login</a>
        <p></p>
        <a href="client/account/logout">click here to logout</a>
    </div>
}
```
</p>
</details>

## Part 1 milestone: Test login
This is a milestone, login and logout could now be tested.
When logging in, you should be redirected to Auth0 login page.
When prompted with login from Auth0, sign up with an email and password of your choice.
To verify that you are actually logged in, go to the browser console and check if a cookie named `.AspNetCore.Cookies` is present.
Also try logging out, and logging in again and verify that you are prompted with login again.

If anything fails, it should be fixed before moving on.

Debugging tips:
- Use fiddler to inspect the communication between the BFF and the IDP. See [appendix](#debugging-net-with-fiddler)
- Use browser tools and inspect the console and network.
- Compare with [solution](1-login-and-logout)

# Workshop guide part 2 - User context
This parts is about adding an authentication context to the frontend.

## User controller
The user controller should return authentication state. This state is intended for the client.
Create a user info record like below:

``` csharp
public record UserInfo(
    bool IsAuthenticated,
    List<KeyValuePair<string, string>> Claims);
```

Create a user controller with the current endpoint:

**client/account/user:** This endpoint should be a http get, and accept no parameters.
It should return a `UserInfo` record. `UserInfo` should be populated with data from the `UserPrincipal`.
The `UserPrincipal` can be accessed with the property `User` from the `ControllerBase`. This object contains authentication states and all claims.
When adding claims to `UserInfo`, make sure to only add the claims we need.
We do not want to expose all claims for security reasons.
For now, expose only the claim named `name`.

<details>
<summary><b>Spoiler (Full code)</b></summary>
<p>

``` csharp
[ApiController]
[Route("client/[controller]")]
public class UserController : ControllerBase
{
    [HttpGet]
    [ProducesResponseType(typeof(UserInfo), StatusCodes.Status200OK)]
    public IActionResult GetCurrentUser()
    {
        var claimsToExpose = new List<string>()
        {
            "name"
        };

        var user = new UserInfo(
            User.Identity?.IsAuthenticated ?? false,
            User.Claims
                .Select(c => new KeyValuePair<string, string>(c.Type, c.Value))
                .Where(c => claimsToExpose.Contains(c.Key))
                .ToList());

        return Ok(user);
    }
}
```
</p>
</details>

## Authentication state in frontend
The frontend needs to fetch the authentication state from the userinfo endpoint, and save it as state.
There are several ways to to this in a react application, but I recommend using react context, and wrapping the entire app in an AuthProvider.
Sample code is below, but feel free to do this without looking at the sample code if you want to, or save the auth state a different way if you want to.

<details>
<summary><b>AuthContext.js</b></summary>
<p>

``` js
import { createContext } from "react";
const AuthContext = createContext();
export default AuthContext;
```
</p>
</details>

<details>
<summary><b>AuthProvider.js</b></summary>
<p>

``` js
import { useState, useEffect } from 'react';
import { getUser } from './userService.js'
import AuthContext from './AuthContext'
export const AuthProvider = ({ children }) => {
    const [user, setUser] = useState(null);
    useEffect(() => {
        getUser()
            .then(response => { setUser(response) })
            .catch(e => setUser({ isAuthenticated: false }))
    }, []);

    return (
        <AuthContext.Provider value={{ user }}>{children}</AuthContext.Provider>
    );
};
```
</p>
</details>

<details>
<summary><b>useAuthContext.js</b></summary>
<p>

``` js
import AuthContext from "./AuthContext";
import { useContext } from "react";
export const useAuthContext = () => {
    const user = useContext(AuthContext);
    if (user === undefined) {
        throw new Error("useAuthContext can only be used inside AuthProvider");
    }
    return user;
};
```
</p>
</details>

<details>
<summary><b>userService.js</b></summary>
<p>

``` js
export async function getUser() {
    const response = await fetch('client/user');
    return response.json();
}
```
</p>
</details>

Wrap the `App` component in the provider in `ìndex.js`
``` js
<AuthProvider>
    <App />
</AuthProvider>
```

## Login and logout button
Now that we have an authentication state, we can modify our login component to only show login or logout.

Get the auth state from `useAuthContext.js` if you saved the state as suggested.
As this to conditionally render login or logout.
Also render the name of the logged in person when logged in. The name can be fetched from the claims.

Example component below.

<details>
<summary><b>Authentication.js</b></summary>
<p>

``` js
import { useAuthContext } from "../auth/useAuthContext";
import React from "react";
import { useLocation } from "react-router-dom";

export function Authentication() {
    const context = useAuthContext();
    const location = useLocation();

    return context?.user?.isAuthenticated
        ? <a href="client/account/logout">
            click here to logout (logged in as {context?.user?.claims?.find(x => x.key === 'name')?.value})</a>
        : <a href={`client/account/login?returnUrl=${location.pathname}`}>click here to login</a>;
}
```
</p>
</details>

## Part 2 milestone: Test user context
This is a milestone, user context can now be tested.
If anything fails, it should be fixed before moving on.

Debugging tips:
- Use fiddler to inspect the communication between the BFF and the IDP. See [appendix](#debugging-net-with-fiddler)
- Use browser tools and inspect the console and network.
- Compare with [solution](2-user-context)

When prompted with login from Auth0, sign up with an email and password of your choice.

# Workshop guide part 3 - Accessing remote API
We will now connect to the weather forecast API.
- Base uri: https://oidccourseapi.azurewebsites.net
- Audience: `weather_forecast_api`
- Scope: `read:forecast`

## Bootstrapping
To get an access token for the API we need to request the API scope.
Add the scope to the options in `AddOpenIdConnect`.

Auth0 also requires that audience is specified when requesting scope for an API.
This is not always required by all IDPs. The `OnRedirectToIdentityProvider` event allows us to add a property with the audience of the API.
Add the following code to the event:

``` csharp
context.ProtocolMessage.SetParameter("audience", "weather_forecast_api");
```

## Exchanging cookie for access token
The access token is located is accessible through the HttpContext. We are using a reverse proxy for all API requests.
We can configure a transform on the proxy that adds the access token to the request.
``` csharp
builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    .AddTransforms(builderContext =>
    {
        builderContext.AddRequestTransform(async transformContext =>
        {
            var accessToken = await transformContext.HttpContext.GetTokenAsync("access_token");
            if (accessToken != null)
            {
                transformContext.ProxyRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            }
        });
    });
```

## Part 3 milestone: Test API access
Test that access we now can access the weather forecast when we are logged in.
If anything fails, it should be fixed before moving on.

Debugging tips:
- Set breakpoint inside `AddRequestTransform` and inspect the access token using https://jwt.io
- Compare with [solution](3-accessing-remote-api)

# Workshop guide part 4 - Refreshing the token
If you have not noticed, the access token has a 60s time to live. When it expires, the token is no longer valid.
We want to refresh the access token when this happens.

## Dependencies
Microsoft does not support refresh token management with their handler.
There are some frameworks that does support this. We are going to du it in the easiest way possible,
and download `IdentityModel.AspNetCore`. This framework is deprecated and replaced by Duende Identity Server (requires payment),
so don't use this in real apps.

Refresh token handling can also be implemented without any framework. This is a completely viable solution, 
just make sure you have knowledge of best practices related to this. We are doing it the easy way though.

Install the following dependencies using Nuget
- IdentityModel.AspNetCore

## Bootstrapping
We need to request the `offlie_access` scope. This will instruct the identity provider to giv us a refresh token.

Add the token management from IdentityModel, and configure the when we should refresh.
In this code we will refresh a token if the access token have less than 30 seconds to live, or if it is expired. 
``` csharp
builder.Services.AddUserAccessTokenManagement(options =>
{
    options.RefreshBeforeExpiration = TimeSpan.FromSeconds(30);
});
```

When signing out it is important that the refresh token is revoked.
This will trigger a request to the IDP revoking the refresh token.
This makes sure that the refresh token cannot be used after a session is ended.
``` csharp
options.Events.OnSigningOut = async context =>
{
    await context.HttpContext.RevokeUserRefreshTokenAsync();
};
```

## Trigger refresh
IdentityModel.AspNetCore has a delegating handler called `UserAccessTokenHandler` that is intended for `HttpClient`.
The handler will check if the access token needs to be refreshed, and perform refresh if necessary.
It will also add the access token to the request header.
We are not using a `HttpClient` directly, so we need to modify the YARP proxy client.

First register the delegating handler:
``` csharp
builder.Services.AddTransient<UserAccessTokenHandler>();
```

Then create a new class called `UserAccessTokenProxyHttpClientFactory`.
``` csharp
public class UserAccessTokenProxyHttpClientFactory : IForwarderHttpClientFactory
{
    private readonly UserAccessTokenHandler _userAccessTokenHandler;

    public UserAccessTokenProxyHttpClientFactory(UserAccessTokenHandler userAccessTokenHandler)
    {
        _userAccessTokenHandler = userAccessTokenHandler;

        var handler = new SocketsHttpHandler
        {
            UseProxy = false,
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.None,
            UseCookies = false,
            ActivityHeadersPropagator = new ReverseProxyPropagator(DistributedContextPropagator.Current)
        };

        _userAccessTokenHandler.InnerHandler = handler;
    }

    public HttpMessageInvoker CreateClient(ForwarderHttpClientContext context)
    {
        if (context.OldClient != null && context.NewConfig == context.OldConfig)
        {
            return context.OldClient;
        }

        return new HttpMessageInvoker(_userAccessTokenHandler, disposeHandler: false);
    }
}
```

Then register this so that it overrides the default implementation from YARP:
``` csharp
builder.Services.AddTransient<IForwarderHttpClientFactory, UserAccessTokenProxyHttpClientFactory>();
```

Now that we are using the `UserAccessTokenHandler` we dont need the `AddTransforms` on the proxy anymore.
Remove the code previously added.

## Part 4 milestone: Test token refresh
Test that you can still access the weather forecast after waiting more than 60s after login.

Debugging tips:
- Use fiddler to inspect the communication between the BFF and the IDP. See [appendix](#debugging-net-with-fiddler)
- Compare with [solution](4-refreshing-the-token)

# Workshop guide done
Congrats, you are now done. If you have time left, feel free to improve your app.

Suggested improvements:
- Add anti-forgery token for protection against CSRF from sub domains.
- Add Content Security Policy (CSP) for protection against cross-site scripting (XSS)
- Advanced: Implement a server side session store by implementing the `ITicketStore` interface. Can be configured in cookie options.
- Advanced: implement automatic refresh of tokens without using IdentityModel.AspNetCore.

For additional suggestions for improvements, ask your course teacher.

# Appendix
## Debugging .NET with Fiddler
### HTTPS
To view https traffic in fiddler, go to **Tools -> Fiddler Options -> HTTPS** and activate HTTPS by checking the boxes shown below
![alt text](Resources/fiddler_https.PNG?raw=true)

### Capture .NET traffic
Fiddler relies on proxies to intercept requests. To inspect all traffic from .NET a proxy must be added.
Open `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\machine.config` and add the following code section at the bottom immediately after `</system.web>`

``` xml
<system.net>
    <defaultProxy enabled = "true" useDefaultCredentials = "true">
        <proxy autoDetect="false" bypassonlocal="false" proxyaddress="http://127.0.0.1:8888" usesystemdefault="false" />
    </defaultProxy>
</system.net>
```

This will allow fiddler to read .NET traffic.

**NB:** remember to remove the proxy when finished.

### Use filters
Use filters to not get overloaded with traffic that is not interesting.

Recommended host filters for this application: `dev-my7g8x3rrwfzi3lh.eu.auth0.com; localhost:5001; localhost:44469;`

![alt text](Resources/fiddler_filter.PNG?raw=true)
