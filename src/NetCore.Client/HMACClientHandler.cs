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

        public HmacClientHandler(
            string appId,
            SecureString secret,
            ISigningAlgorithm signingAlgorithm,
            INonceGenerator nonceGenerator = null,
            ITime time = null)
        {
            this.appId = appId;
            this.secret = secret;
            this.signingAlgorithm = signingAlgorithm;
            this.nonceGenerator = nonceGenerator ?? GuidNonceGenerator.Instance;
            this.time = time ?? SystemTime.Instance;
        }

        public HmacClientHandler(
            HttpMessageHandler innerHandler,
            string appId,
            SecureString secret,
            ISigningAlgorithm signingAlgorithm,
            INonceGenerator nonceGenerator = null,
            ITime time = null)
            : base(innerHandler)
        {
            this.appId = appId;
            this.secret = secret;
            this.signingAlgorithm = signingAlgorithm;
            this.nonceGenerator = nonceGenerator ?? GuidNonceGenerator.Instance;
            this.time = time ?? SystemTime.Instance;
        }

        protected override HttpRequestMessage ProcessRequest(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var nonce = nonceGenerator.NextNonce;
            var timestamp = time.UtcNow;

            var builder = new CannonicalRepresentationBuilder();
            var content = builder.BuildRepresentation(
                nonce,
                appId,
                request.Method.Method,
                request.Content?.Headers?.ContentType?.ToString(),
                string.Join(", ", request.Headers.Accept),
                request.Content?.Headers?.ContentMD5,
                timestamp,
                request.RequestUri);

            var signature = signingAlgorithm.Sign(secret, content);

            request.Headers.Authorization = new AuthenticationHeaderValue(Schemas.HMAC, signature);
            request.Headers.Add(Headers.XAppId, appId);
            request.Headers.Add(Headers.XNonce, nonce);
            request.Headers.Date = timestamp;

            return request;
        }

        protected override HttpResponseMessage ProcessResponse(HttpResponseMessage response, CancellationToken cancellationToken) => response;
    }
}