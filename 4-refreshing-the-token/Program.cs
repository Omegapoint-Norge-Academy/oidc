using System.Web;
using IdentityModel.AspNetCore.AccessTokenManagement;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using OIDC.Course;
using Yarp.ReverseProxy.Forwarder;

var builder = WebApplication.CreateBuilder(args);

builder.Services
    .AddAuthentication(options =>
    {
        options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
    })
    .AddCookie(options =>
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
        
        options.Events.OnSigningOut = async context =>
        {
            await context.HttpContext.RevokeUserRefreshTokenAsync();
        };
    })
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
        options.Scope.Add("read:forecast");
        options.Scope.Add("offline_access");

        options.Events.OnRedirectToIdentityProvider = context =>
        {
            if (context.Request.Path.StartsWithSegments("/api") ||
                context.Request.Path.StartsWithSegments("/client/user"))
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                context.HandleResponse();
            }
            
            // Auth0 specific implementation
            context.ProtocolMessage.SetParameter("audience", "weather_forecast_api");
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
    });

builder.Services.AddAuthorization(options =>
{
    var defaultPolicy = new AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .Build();
    
    options.AddPolicy("AuthenticatedUser", defaultPolicy);
    options.DefaultPolicy = defaultPolicy;
    options.FallbackPolicy = defaultPolicy;
});

builder.Services.AddUserAccessTokenManagement(options =>
{
    options.RefreshBeforeExpiration = TimeSpan.FromSeconds(30);
});

builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"));

builder.Services.AddTransient<UserAccessTokenHandler>();
builder.Services.AddTransient<IForwarderHttpClientFactory, UserAccessTokenProxyHttpClientFactory>();

builder.Services.AddControllersWithViews();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers().RequireAuthorization("AuthenticatedUser");
app.MapReverseProxy().RequireAuthorization("AuthenticatedUser");

app.MapFallbackToFile("index.html");

app.Run();