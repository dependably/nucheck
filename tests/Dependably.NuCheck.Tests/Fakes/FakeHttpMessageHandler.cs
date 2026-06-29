using System.Net;
using System.Text;

namespace Dependably.NuCheck.Tests.Fakes;

/// <summary>An HttpMessageHandler that returns a canned response, for client tests.</summary>
public sealed class FakeHttpMessageHandler : HttpMessageHandler
{
    private readonly Func<HttpRequestMessage, (HttpStatusCode Status, string Body)> _responder;

    public FakeHttpMessageHandler(Func<HttpRequestMessage, (HttpStatusCode, string)> responder)
        => _responder = responder;

    public FakeHttpMessageHandler(HttpStatusCode status, string body)
        : this(_ => (status, body))
    {
    }

    public HttpRequestMessage? LastRequest { get; private set; }

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        LastRequest = request;
        var (status, body) = _responder(request);
        return Task.FromResult(new HttpResponseMessage(status)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json"),
        });
    }
}
