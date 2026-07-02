using System.Net;
using System.Text;

namespace Dependably.NuCheck.Tests.Fakes;

/// <summary>An HttpMessageHandler that returns a canned response, for client tests.</summary>
public sealed class FakeHttpMessageHandler : HttpMessageHandler
{
    private readonly Func<HttpRequestMessage, HttpResponseMessage> _responder;

    public FakeHttpMessageHandler(Func<HttpRequestMessage, HttpResponseMessage> responder)
        => _responder = responder;

    public FakeHttpMessageHandler(Func<HttpRequestMessage, (HttpStatusCode Status, string Body)> responder)
        : this(req =>
        {
            var (status, body) = responder(req);
            return new HttpResponseMessage(status)
            {
                Content = new StringContent(body, Encoding.UTF8, "application/json"),
            };
        })
    { }

    public FakeHttpMessageHandler(HttpStatusCode status, string body)
        : this(_ => (status, body))
    { }

    public HttpRequestMessage? LastRequest { get; private set; }

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        LastRequest = request;
        return Task.FromResult(_responder(request));
    }
}
