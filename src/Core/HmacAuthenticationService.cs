using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security;
using System.Security.Cryptography;

namespace Security.HMAC
{
    public interface IHmacAuthenticationService
    {
        HmacAuthenticationResult Authenticate(HttpRequestMessage msg);
    }

    public class HmacAuthenticationService : IHmacAuthenticationService
    {
        private readonly IAppSecretRepository appSecretProvider;
        private readonly ISigningAlgorithm algorithm;
        private readonly IHmacRequestDateValidator dateValidator;
        private readonly IHmacSignatureContentResolver signatureContentResolver;

        public HmacAuthenticationService(
            IAppSecretRepository appSecretProvider,
            ISigningAlgorithm algorithm,
            IHmacRequestDateValidator dateValidator, 
            IHmacSignatureContentResolver signatureContentResolver)
        {
            this.appSecretProvider = appSecretProvider;
            this.algorithm = algorithm;
            this.dateValidator = dateValidator;
            this.signatureContentResolver = signatureContentResolver;
        }

        public HmacAuthenticationResult Authenticate(HttpRequestMessage msg)
        {
            string clientSignature = ResolveSignature(msg.Headers);

            HmacSignatureContent signatureContent = signatureContentResolver.Resolve(msg);
            dateValidator.Validate(signatureContent.Date);

            SecureString secret = GetAppSecret(signatureContent.AppId);
            string signature = algorithm.Sign(secret, signatureContent.ToCanonicalString());

            if (signature != clientSignature)
                throw new HmacAuthenticationException("Signature mismatch");

            return new HmacAuthenticationResult(signatureContent.AppId);
        }

        private SecureString GetAppSecret(string appId)
        {
            SecureString secret = appSecretProvider.GetSecret(appId);

            if (secret == null || secret.Length == 0)
                throw new HmacAuthenticationException($"App secret key not found: '{appId}'");

            return secret;
        }

        private string ResolveSignature(HttpRequestHeaders headers)
        {
            AuthenticationHeaderValue header = headers.Authorization;

            if (header == null)
                throw new HmacAuthenticationException("'Authorization' header is not present");

            if (header.Scheme != Schemas.HMAC)
                throw new HmacAuthenticationException($"Invalid authorization schema: '{header.Scheme}'");

            if (string.IsNullOrWhiteSpace(header.Parameter))
                throw new HmacAuthenticationException("HMAC signature is not missing");

            return header.Parameter;
        }

        public static HmacAuthenticationService Create(HmacOptions options)
        {
            return new HmacAuthenticationService(
                options.AppSecretRepository,
                options.Algorithm,
                new HmacRequestDateValidator(options.Time, options.ClockSkew),
                new HmacSignatureContentResolver(new RequestUrlResolver(options.RequestProtocol, options.Host)));
        }
    }
}