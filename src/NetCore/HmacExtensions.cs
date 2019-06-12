using System;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Security.HMAC
{
    public static class HmacExtensions
    {
        [Obsolete("Use AddHmacAuthentication instead")]
        public static void AddHmac(this IServiceCollection services, IConfigurationSection config) => RegisterServices(services, config);

        [Obsolete("Use AddHmacAuthentication instead")]
        public static void AddHmac(this IServiceCollection services, HmacOptions options) => RegisterServices(services, options);

        [Obsolete("Use AddHmacAuthentication instead")]
        public static IApplicationBuilder UseHmac(this IApplicationBuilder builder) => builder.UseMiddleware<HmacMiddleware>();

        public static AuthenticationBuilder AddHmacAuthentication(this AuthenticationBuilder builder, IConfigurationSection config)
        {
            RegisterServices(builder.Services, config);
            return builder.AddScheme<AuthenticationSchemeOptions, HmacAuthenticationHandler>(Schemas.HMAC, o => { });
        }

        public static AuthenticationBuilder AddHmacAuthentication(this AuthenticationBuilder builder, HmacOptions options)
        {
            RegisterServices(builder.Services, options);
            return builder.AddScheme<AuthenticationSchemeOptions, HmacAuthenticationHandler>(Schemas.HMAC, o => { });
        }

        private static void RegisterServices(IServiceCollection services, IConfigurationSection config)
        {
            var options = new HmacOptions(new SecretsFromConfig(config.GetSection("Secrets")));
            config.Bind(options);

            RegisterServices(services, options);
        }

        private static void RegisterServices(this IServiceCollection services, HmacOptions options)
        {
            services.AddSingleton<IHmacAuthenticationService>(HmacAuthenticationService.Create(options));
        }

    }
}
