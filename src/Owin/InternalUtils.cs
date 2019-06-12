using System.Net.Http;
using Microsoft.Owin;

namespace Security.HMAC
{
    internal static class InternalUtils
    {
        public static HttpRequestMessage ToRequestMessage(this IOwinRequest request)
        {
            var msg = new HttpRequestMessage(new HttpMethod(request.Method), request.Uri);

            foreach (var header in request.Headers)
                msg.Headers.TryAddWithoutValidation(header.Key, header.Value);

            return msg;
        }
    }
}