using System.Security;

namespace Security.HMAC
{
    public interface IAppSecretRepository
    {
        SecureString GetSecret(string appId);
    }
}