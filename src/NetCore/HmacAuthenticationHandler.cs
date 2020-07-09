using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;

namespace Security.HMAC
{
    public class HmacAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
    {
        private readonly IHmacAuthenticationService authenticationService;

        public HmacAuthenticationHandler(
            IOptionsMonitor<AuthenticationSchemeOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock,
            IHmacAuthenticationService authenticationService)
            : base(options, logger, encoder, clock)
        {
            this.authenticationService = authenticationService;
        }

        protected override Task<AuthenticateResult> HandleAuthenticateAsync() => Task.FromResult(HandleAuthenticate());

        private AuthenticateResult HandleAuthenticate()
        {
            try
            {
                return ShouldAuthenticate(Request.Headers)
                    ? Authenticate()
                    : AuthenticateResult.NoResult();
            }
            catch (HmacAuthenticationException e)
            {
                return AuthenticateResult.Fail(e);
            }
        }

        private AuthenticateResult Authenticate()
        {
            HmacAuthenticationResult auth = authenticationService.Authenticate(Request.ToRequestInfo());

            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, auth.AppId),
                new Claim(ClaimTypes.AuthenticationMethod, Schemas.HMAC)
            };
            ClaimsPrincipal principal = new ClaimsPrincipal(new ClaimsIdentity(claims, Scheme.Name));
            AuthenticationTicket ticket = new AuthenticationTicket(principal, Scheme.Name);

            return AuthenticateResult.Success(ticket);
        }

        private static bool ShouldAuthenticate(IHeaderDictionary headers)
        {
            if (false == headers.TryGetValue(Headers.Authorization, out StringValues header))
                return false;

            var authorizationHeader = AuthenticationHeaderValue.Parse(header);

            return authorizationHeader.Scheme == Schemas.HMAC;
        }
    }
}
