using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace WebAuthn.Net.DSL.Fakes;

public class FakeFidoMetadataDelegatingHandler : DelegatingHandler
{
    private static readonly byte[] FakeResponse = Encoding.UTF8.GetBytes(EmbeddedResourceProvider.GetString("WebAuthn.Net.DSL.Fakes.FakeResources.FakeFidoMetadata.txt"));
    private bool _returnNotFoundPermanent;

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(CreateResponse());
    }

    protected override HttpResponseMessage Send(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();
        return CreateResponse();
    }

    private HttpResponseMessage CreateResponse()
    {
        if (_returnNotFoundPermanent)
        {
            return CreateNotFoundResponse();
        }

        return CreateFileResponse();
    }

    private static HttpResponseMessage CreateFileResponse()
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK);
        response.Content = new ByteArrayContent(FakeResponse);
        response.Content.Headers.ContentType = new("application/octet-stream");
        response.Content.Headers.ContentDisposition = ContentDispositionHeaderValue.Parse("attachment; filename=blob.jwt");
        return response;
    }

    private static HttpResponseMessage CreateNotFoundResponse()
    {
        var response = new HttpResponseMessage(HttpStatusCode.NotFound);
        return response;
    }

    public void ReturnNotFound()
    {
        _returnNotFoundPermanent = true;
    }
}
