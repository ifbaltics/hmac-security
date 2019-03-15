namespace Security.HMAC
{
    using System;
    using Microsoft.AspNetCore.Authentication;
    public class HmacAuthenticationHandlerOptions : AuthenticationSchemeOptions
    {
        public TimeSpan ClockSkew { get; set; }
        public string RequestProtocol { get; set; }
    }
}
