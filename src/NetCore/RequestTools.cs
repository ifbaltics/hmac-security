namespace Security.HMAC
{
    using System;
    using System.Net;
    using System.Net.Http.Headers;
    using System.Security;
    using Microsoft.AspNetCore.Http;
    using Microsoft.AspNetCore.Http.Extensions;

    internal static class RequestTools
    {
        internal static bool Validate(HttpRequest req, ISigningAlgorithm algorithm, IAppSecretRepository secretRepository, ITime time, TimeSpan clockSkew)
        {
            var h = req.Headers;

            var appId = GetAppId(req);
            var nonce = GetNonce(req);

            var authHeader = h.Get(Headers.Authorization);
            var auth = authHeader.HasValue
                ? AuthenticationHeaderValue.Parse(authHeader)
                : null;
            var authSchema = auth?.Scheme;
            var authValue = auth?.Parameter;
            DateTimeOffset date =
                DateTimeOffset.TryParse(h.Get(Headers.Date), out date)
                    ? date
                    : DateTimeOffset.MinValue;

            if (appId != null
                && nonce != null
                && authSchema == Schemas.HMAC
                && authValue != null
                && time.UtcNow - date <= clockSkew)
            {
                string contentMd5 = h.Get(Headers.ContentMD5);
                var builder = new CannonicalRepresentationBuilder();

                var url = h.Get(Headers.XOriginalUrl);
                url = string.IsNullOrWhiteSpace(url) ? req.GetEncodedUrl() : $"https://{req.Host.Host}{url}";

                var content = builder.BuildRepresentation(
                    nonce,
                    appId,
                    req.Method,
                    req.ContentType,
                    req.Headers.Get("Accept"),
                    contentMd5 == null ? null : Convert.FromBase64String(contentMd5),
                    date,
                    new Uri(url));

                SecureString secret;
                if (content != null && (secret = secretRepository.GetSecret(appId)) != null)
                {
                    var signature = algorithm.Sign(secret, content);
                    if (authValue == signature)
                    {
                        return true;
                    }
                }
            }

            return false;
        }

        public static string GetAppId(HttpRequest req) => req.Headers.Get(Headers.XAppId);

        public static string GetNonce(HttpRequest req) => req.Headers.Get(Headers.XNonce);
    }
}