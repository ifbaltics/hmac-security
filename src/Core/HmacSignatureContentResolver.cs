using System;
using System.Collections.Generic;
using System.Linq;

namespace Security.HMAC
{
    public interface IHmacSignatureContentResolver
    {
        HmacSignatureContent Resolve(HmacRequestInfo req);
    }

    public class HmacSignatureContentResolver : IHmacSignatureContentResolver
    {
        private readonly IRequestUrlResolver urlResolver;

        public HmacSignatureContentResolver(IRequestUrlResolver urlResolver)
        {
            this.urlResolver = urlResolver;
        }

        public HmacSignatureContent Resolve(HmacRequestInfo req)
        {
            var request = new HmacSignatureContent
            {
                Method = req.Method,
                Uri = urlResolver.Resolve(req),
                Nonce = req.Headers.Required(Headers.XNonce),
                AppId = req.Headers.Required(Headers.XAppId),
                Date = GetDate(req.Headers),
                Accepts = string.Join(", ", req.Headers.All(Headers.Accept)),
                ContentType = req.Headers.FirstOrDefault(Headers.ContentType),
                ContentMd5 = Md5(req.Headers)
            };

            return request;
        }

        private static byte[] Md5(IEnumerable<KeyValuePair<string, string>> headers)
        {
            var header = headers.FirstOrDefault(Headers.ContentMd5);
            if (string.IsNullOrEmpty(header)) return null;

            return Convert.FromBase64String(header);
        }

        private static DateTimeOffset GetDate(IEnumerable<KeyValuePair<string, string>> headers)
        {
            var header = headers.Required("Date");

            if (DateTimeOffset.TryParse(header, out DateTimeOffset date) == false)
                throw new HmacAuthenticationException("'Date' header is not well formatted.");

            return date;
        }
    }
}