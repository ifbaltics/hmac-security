namespace Security.HMAC
{
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Security;
    using System.Threading;

    public sealed class HmacClientHandler : MessageProcessingHandler
    {
        private readonly string appId;
        private readonly SecureString secret;
        private readonly ISigningAlgorithm signingAlgorithm;
        private readonly INonceGenerator nonceGenerator;
        private readonly ITime time;

        // for service collection
        public HmacClientHandler(
            string appId,
            SecureString secret,
            ISigningAlgorithm signingAlgorithm = null,
            INonceGenerator nonceGenerator = null,
            ITime time = null)
        {
            this.appId = appId;
            this.secret = secret;
            this.signingAlgorithm = signingAlgorithm ?? HmacSigningAlgorithm.Default;
            this.nonceGenerator = nonceGenerator ?? GuidNonceGenerator.Instance;
            this.time = time ?? SystemTime.Instance;
        }

        public HmacClientHandler(
            HttpMessageHandler innerHandler,
            string appId,
            SecureString secret,
            ISigningAlgorithm signingAlgorithm = null,
            INonceGenerator nonceGenerator = null,
            ITime time = null)
            : base(innerHandler)
        {
            this.appId = appId;
            this.secret = secret;
            this.signingAlgorithm = signingAlgorithm ?? HmacSigningAlgorithm.Default;
            this.nonceGenerator = nonceGenerator ?? GuidNonceGenerator.Instance;
            this.time = time ?? SystemTime.Instance;
        }

        protected override HttpRequestMessage ProcessRequest(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var nonce = nonceGenerator.NextNonce;
            var timestamp = time.UtcNow;

            var content = new HmacSignatureContent
            {
                Nonce = nonce,
                AppId = appId,
                Date = timestamp,
                Method = request.Method.Method,
                Accepts = string.Join(", ", request.Headers.Accept),
                ContentType = request.Content?.Headers?.ContentType?.ToString(),
                ContentMd5 = request.Content?.Headers?.ContentMD5,
                Uri = request.RequestUri
            };

            var signature = signingAlgorithm.Sign(secret, content.ToCanonicalString());

            request.Headers.Authorization = new AuthenticationHeaderValue(Schemas.HMAC, signature);

            SetHeader(request, Headers.XAppId, appId);
            SetHeader(request, Headers.XNonce, nonce);

            request.Headers.Date = timestamp;

            return request;
        }

        private static void SetHeader(HttpRequestMessage request, string name, string value)
        {
            if (request.Headers.Contains(name))
                request.Headers.Remove(name);

            request.Headers.Add(name, value);
        }

        protected override HttpResponseMessage ProcessResponse(HttpResponseMessage response, CancellationToken cancellationToken) => response;
    }
}