using System.Collections.Concurrent;
using System.Security;
using Microsoft.Extensions.Configuration;

namespace Security.HMAC
{
    public class SecretsFromConfig : IAppSecretRepository
    {
        public SecretsFromConfig(IConfigurationSection secretsSection)
        {
            this.secretsSection = secretsSection;
        }

        private readonly IConfigurationSection secretsSection;
        private readonly ConcurrentDictionary<string, SecureString> secrets =
            new ConcurrentDictionary<string, SecureString>();

        public SecureString GetSecret(string client)
        {
            return secrets.GetOrAdd(client, GetClientSecret);
        }

        private SecureString GetClientSecret(string client)
        {
            string secretStr = secretsSection.GetValue<string>(client);
            return secretStr.ToSecureString();
        }
    }
}