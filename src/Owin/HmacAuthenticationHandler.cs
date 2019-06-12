using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;

namespace Security.HMAC
{
    public class HmacAuthenticationHandler : AuthenticationHandler<HmacAuthenticationOptions>
    {
        private readonly IHmacAuthenticationService authenticationService;

        public HmacAuthenticationHandler(IHmacAuthenticationService authenticationService)
        {
            this.authenticationService = authenticationService;
        }

        protected override Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            try
            {
                return Task.FromResult(Authenticate());
            }
            catch (HmacAuthenticationException)
            {
                return Task.FromResult<AuthenticationTicket>(null);
            }
        }

        private AuthenticationTicket Authenticate()
        {
            HmacAuthenticationResult result = authenticationService.Authenticate(Request.ToRequestMessage());

            Claim claim = new Claim(ClaimTypes.NameIdentifier, result.AppId);

            return new AuthenticationTicket(
                new ClaimsIdentity(new[] { claim }, Schemas.HMAC),
                new AuthenticationProperties());
        }
    }
}