using Microsoft.Owin.Security;

namespace Security.HMAC
{
    public class HmacAuthenticationOptions : AuthenticationOptions
    {
        public readonly HmacOptions Hmac;

        public HmacAuthenticationOptions(HmacOptions options) : base(Schemas.HMAC)
        {
            Hmac = options;
        }
    }
}