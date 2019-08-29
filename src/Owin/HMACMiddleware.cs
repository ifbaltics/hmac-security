using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Owin;

namespace Security.HMAC
{
    public class HmacMiddleware : OwinMiddleware
    {
        private readonly IHmacAuthenticationService authenticationService;

        public HmacMiddleware(OwinMiddleware next, HmacOptions middlewareOptions)
            : base(next)
        {
            authenticationService = HmacAuthenticationService.Create(middlewareOptions);
        }

        public override async Task Invoke(IOwinContext context)
        {
            if (Authenticated(context))
            {
                await Next.Invoke(context);
            }
            else
            {
                context.Response.StatusCode = 401;
                context.Response.Headers.Append(Headers.WWWAuthenticate, Schemas.HMAC);
            }
        }

        private bool Authenticated(IOwinContext context)
        {
            try
            {
                authenticationService.Authenticate(context.Request.ToRequestInfo());
                return true;
            }
            catch (HmacAuthenticationException)
            {
                return false;
            }
        }
    }
}
