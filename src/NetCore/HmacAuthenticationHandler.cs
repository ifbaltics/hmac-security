namespace Security.HMAC
{
    using System;
    using System.Security.Claims;
    using System.Text.Encodings.Web;
    using System.Threading.Tasks;
    using Microsoft.Extensions.Logging;
    using Microsoft.Extensions.Options;
    using Microsoft.AspNetCore.Authentication;
    public class HmacAuthenticationHandler : AuthenticationHandler<HmacAuthenticationHandlerOptions>
    {
        private readonly ISigningAlgorithm algorithm;
        private readonly IAppSecretRepository secretRepository;
        private readonly ITime time;
        public HmacAuthenticationHandler(
            IOptionsMonitor<HmacAuthenticationHandlerOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock,
            ISigningAlgorithm algorithm,
            IAppSecretRepository secretRepository,
            ITime time)
            : base(options, logger, encoder, clock)
        {
            this.algorithm = algorithm;
            this.secretRepository = secretRepository;
            this.time = time;
        }

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (!Request.Headers.ContainsKey(Headers.Authorization))
                return Task.FromResult(AuthenticateResult.Fail("Missing Authorization Header"));


            if (RequestTools.Validate(Request, this.algorithm, this.secretRepository, this.time, Options.ClockSkew, Options.RequestProtocol))
            {
                var claims = new[] { new Claim("Application", RequestTools.GetAppId(Request)) };
                var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, Scheme.Name));
                var ticket = new AuthenticationTicket(principal, Scheme.Name);
                return Task.FromResult(AuthenticateResult.Success(ticket));
            }

            return Task.FromResult(AuthenticateResult.Fail("Authentication failed"));
        }
    }
}
