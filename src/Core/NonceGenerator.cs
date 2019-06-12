using System;

namespace Security.HMAC
{
    public interface INonceGenerator
    {
        string NextNonce { get; }
    }

    public class GuidNonceGenerator : INonceGenerator
    {
        public static readonly INonceGenerator Instance = new GuidNonceGenerator();

        public string NextNonce => Guid.NewGuid().ToString("N");
    }
}