using System;
using Owin;

namespace Security.HMAC
{
    public static class HmacExtensions
    {
        public static void UseHmacAuthentication(this IAppBuilder app, HmacAuthenticationOptions options)
        {
            app.Use<HmacAuthenticationMiddleware>(options);
        }

        [Obsolete("Use HmacAuthentication instead")]
        public static void UseHmac(this IAppBuilder app, HmacOptions options)
        {
            app.Use<HmacMiddleware>(options);
        }
    }
}