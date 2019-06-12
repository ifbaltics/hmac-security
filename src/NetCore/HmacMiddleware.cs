using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace Security.HMAC
{
    public class HmacMiddleware
    {
        private readonly IHmacAuthenticationService authenticationService;
        private readonly ILoggerFactory loggerFactory;
        private readonly RequestDelegate next;

        public HmacMiddleware(
            RequestDelegate next,
            IHmacAuthenticationService authenticationService,
            ILoggerFactory loggerFactory)
        {
            this.next = next;
            this.authenticationService = authenticationService;
            this.loggerFactory = loggerFactory;
        }

        public async Task Invoke(HttpContext context)
        {
            if (Authenticated(context))
            {
                await next(context);
            }
            else
            {
                context.Response.StatusCode = 401;
                context.Response.Headers.Append(Headers.WWWAuthenticate, Schemas.HMAC);
            }
        }

        public bool Authenticated(HttpContext context)
        {
            try
            {
                authenticationService.Authenticate(context.Request.ToRequestMessage());
                return true;
            }
            catch (HmacAuthenticationException e)
            {
                loggerFactory.CreateLogger<HmacMiddleware>()
                    .LogInformation(e, $"HMAC authentication failed: {e.Message}");

                return false;
            }
        }
    }
}
