using System;
using System.Net.Http;
using System.Net.Http.Headers;

namespace Security.HMAC
{
    public interface IHmacSignatureContentResolver
    {
        HmacSignatureContent Resolve(HttpRequestMessage msg);
    }

    public class HmacSignatureContentResolver : IHmacSignatureContentResolver
    {
        private readonly IRequestUrlResolver urlResolver;

        public HmacSignatureContentResolver(IRequestUrlResolver urlResolver)
        {
            this.urlResolver = urlResolver;
        }

        public HmacSignatureContent Resolve(HttpRequestMessage msg)
        {
            var request = new HmacSignatureContent
            {
                Nonce = msg.Headers.Required(Headers.XNonce),
                AppId = msg.Headers.Required(Headers.XAppId),
                Date = GetDate(msg.Headers),
                Method = msg.Method.Method,
                Accepts = string.Join(", ", msg.Headers.Accept),
                Uri = urlResolver.Resolve(msg)
            };

            if (msg.Content != null)
            {
                var contentHeaders = msg.Content.Headers;
                request.ContentType = contentHeaders.ContentType?.ToString();
                request.ContentMd5 = contentHeaders.ContentMD5;

                return request;
            }

            return request;
        }

        private static DateTimeOffset GetDate(HttpRequestHeaders headers)
        {
            var date = headers.Date;

            if (!date.HasValue)
                throw new HmacAuthenticationException("'Date' header is not present");

            return date.Value;
        }
    }
}