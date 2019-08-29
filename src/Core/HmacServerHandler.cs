using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace Security.HMAC
{
    public class HmacServerHandler : DelegatingHandler
    {
        private readonly IHmacAuthenticationService authenticationService;
        private readonly bool mixedMode;

        public HmacServerHandler(HmacOptions options, bool mixedMode = false)
        {
            authenticationService = HmacAuthenticationService.Create(options);
            this.mixedMode = mixedMode;
        }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            bool skip = mixedMode && request.Headers.Authorization?.Scheme != Schemas.HMAC;

            if (skip || Authenticated(request))
                return await base.SendAsync(request, cancellationToken);

            return new HttpResponseMessage(HttpStatusCode.Unauthorized)
            {
                Headers =
                {
                    { Headers.WWWAuthenticate, Schemas.HMAC }
                }
            };
        }

        private bool Authenticated(HttpRequestMessage request)
        {
            try
            {
                authenticationService.Authenticate(request.ToRequestInfo());

                return true;
            }
            catch (HmacAuthenticationException)
            {
                return false;
            }
        }
    }
}