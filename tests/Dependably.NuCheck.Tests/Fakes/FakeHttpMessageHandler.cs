using System.Net;
using System.Text;

namespace Dependably.NuCheck.Tests.Fakes;

/// <summary>An HttpMessageHandler that returns a canned response, for client tests.</summary>
public sealed class FakeHttpMessageHandler : HttpMessageHandler
{
    private readonly Func<HttpRequestMessage, HttpResponseMessage> _responder;

    /// <summary>Full control: the factory builds the complete <see cref="HttpResponseMessage"/>.</summary>
    /// <remarks>
    /// If the factory throws, <see cref="SendAsync"/> surfaces the exception as a faulted
    /// <see cref="Task"/> so the awaiter sees it as a network-level failure.
    /// </remarks>
    public FakeHttpMessageHandler(Func<HttpRequestMessage, HttpResponseMessage> responder)
        => _responder = responder;

    /// <summary>Convenience: specify status + body; the handler sets Content-Type application/json.</summary>
    public FakeHttpMessageHandler(Func<HttpRequestMessage, (HttpStatusCode Status, string Body)> responder)
        : this(req =>
        {
            var (status, body) = responder(req);
            return new HttpResponseMessage(status)
            {
                Content = new StringContent(body, Encoding.UTF8, "application/json"),
            };
        })
    {
    }

    /// <summary>Convenience: constant status + body for all requests.</summary>
    public FakeHttpMessageHandler(HttpStatusCode status, string body)
        : this(_ => (status, body))
    {
    }

    public HttpRequestMessage? LastRequest { get; private set; }

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        LastRequest = request;
        try
        {
            return Task.FromResult(_responder(request));
        }
        catch (Exception ex)
        {
            // Surface exceptions as a faulted task so that callers which await
            // HttpClient.SendAsync see them as network-level failures, not synchronous throws.
            return Task.FromException<HttpResponseMessage>(ex);
        }
    }
}
