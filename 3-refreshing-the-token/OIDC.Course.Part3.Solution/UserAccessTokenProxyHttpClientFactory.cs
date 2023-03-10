using System.Diagnostics;
using System.Net;
using IdentityModel.AspNetCore.AccessTokenManagement;
using Yarp.ReverseProxy.Forwarder;

namespace OIDC.Course.Solution;

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