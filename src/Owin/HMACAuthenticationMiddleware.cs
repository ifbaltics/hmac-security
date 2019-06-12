using Microsoft.Owin;
using Microsoft.Owin.Security.Infrastructure;

namespace Security.HMAC
{
    public class HmacAuthenticationMiddleware : AuthenticationMiddleware<HmacAuthenticationOptions>
    {
        public HmacAuthenticationMiddleware(OwinMiddleware next, HmacAuthenticationOptions authenticationOptions)
            : base(next, authenticationOptions)
        {
        }

        protected override AuthenticationHandler<HmacAuthenticationOptions> CreateHandler()
        {
            return new HmacAuthenticationHandler(HmacAuthenticationService.Create(Options.Hmac));
        }
    }
}