using System;
using System.Net.Http;

namespace Security.HMAC
{
    public interface IRequestUrlResolver
    {
        Uri Resolve(HttpRequestMessage msg);
    }

    public class RequestUrlResolver : IRequestUrlResolver
    {
        private readonly string overrideScheme;
        private readonly string overrideHostname;

        public RequestUrlResolver(string overrideScheme, string overrideHostname)
        {
            this.overrideScheme = overrideScheme;
            this.overrideHostname = overrideHostname;
        }

        public Uri Resolve(HttpRequestMessage msg)
        {
            string ResolveUrlProtocol()
            {
                string p = msg.Headers.FirstOrDefault(Headers.XForwardedProto);
                if (p != null) return p;

                p = msg.Headers.FirstOrDefault(Headers.XForwardedProtocol);
                if (p != null) return p;

                p = msg.Headers.FirstOrDefault(Headers.XUrlScheme);
                if (p != null) return p;

                return !string.IsNullOrWhiteSpace(overrideScheme) ? overrideScheme : msg.RequestUri.Scheme;
            }

            string url = msg.Headers.FirstOrDefault(Headers.XOriginalUrl);

            if (url == null)
                return msg.RequestUri;

            if (Uri.IsWellFormedUriString(url, UriKind.Absolute))
                return new Uri(url);

            string protocol = ResolveUrlProtocol();
            string host = string.IsNullOrWhiteSpace(overrideHostname) ? msg.RequestUri.Host : overrideHostname;

            return new Uri($"{protocol}://{host}{url}");
        }
    }
}