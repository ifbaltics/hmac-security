namespace Security.HMAC
{
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Http;
    using Microsoft.Extensions.Options;

    public class HmacMiddleware
    {
        public HmacMiddleware(
            RequestDelegate next,
            IOptions<HmacMiddlewareOptions> options,
            ISigningAlgorithm algorithm,
            IAppSecretRepository secretRepository,
            ITime time)
        {
            this.options = options;
            this.next = next;
            this.algorithm = algorithm;
            this.secretRepository = secretRepository;
            this.time = time;
        }

        private readonly ISigningAlgorithm algorithm;
        private readonly IAppSecretRepository secretRepository;
        private readonly ITime time;
        private readonly IOptions<HmacMiddlewareOptions> options;
        private readonly RequestDelegate next;

        public async Task Invoke(HttpContext context)
        {
            if (!RequestTools.Validate(
                context.Request,
                algorithm,
                secretRepository,
                time,
                options.Value.ClockSkew,
                options.Value.RequestProtocol))
            {
                var res = context.Response;
                res.StatusCode = 401;
                res.Headers.Append(Headers.WWWAuthenticate, Schemas.HMAC);

                return;
            }

            await next(context);
        }
    }
}
