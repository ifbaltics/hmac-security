using System.Collections.Generic;
using System.Net.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;

namespace Security.HMAC
{
    internal static class InternalUtils
    {
        public static HttpRequestMessage ToRequestMessage(this HttpRequest request)
        {
            var msg = new HttpRequestMessage(new HttpMethod(request.Method), request.GetEncodedUrl())
            {
                Content = new StreamContent(request.Body)
            };

            foreach (var header in request.Headers)
            {
                IEnumerable<string> val = header.Value;
                if (msg.Headers.TryAddWithoutValidation(header.Key, val) == false)
                    msg.Content.Headers.TryAddWithoutValidation(header.Key, val);
            }

            return msg;
        }

    }
}