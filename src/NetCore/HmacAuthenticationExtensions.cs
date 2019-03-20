namespace Security.HMAC
{
    using System;
    using Microsoft.AspNetCore.Authentication;
    using Microsoft.Extensions.Configuration;
    using Microsoft.Extensions.DependencyInjection;
    using System.Security.Cryptography;
    public static class HmacAuthenticationExtensions
    {
        public static AuthenticationBuilder AddHmacAuthentication(this AuthenticationBuilder builder, IConfigurationSection configurationSection)
        {
            return builder.AddHmacAuthentication(new SecretsFromConfig(configurationSection.GetSection("Secrets")),
                new HmacSigningAlgorithm(secret => new HMACSHA256(secret)), opts =>
                {
                    opts.ClockSkew = TimeSpan.Parse(configurationSection.GetValue<string>("ClockSkew"));
                    opts.RequestProtocol = configurationSection.GetValue<string>("RequestProtocol");
                    opts.Host = configurationSection.GetValue<string>("Host");
                });
        }

        public static AuthenticationBuilder AddHmacAuthentication(this AuthenticationBuilder builder, IAppSecretRepository repository, ISigningAlgorithm algorithm, Action<HmacAuthenticationHandlerOptions> configureOptions)
        {
            builder.Services.AddSingleton<ITime, SystemTime>();
            builder.Services.AddSingleton(algorithm);
            builder.Services.AddSingleton(repository);

            return builder.AddScheme<HmacAuthenticationHandlerOptions, HmacAuthenticationHandler>(
                Schemas.HMAC, configureOptions);
        }
    }
}
