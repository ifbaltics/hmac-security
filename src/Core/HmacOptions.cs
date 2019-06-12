using System;
using System.Security.Cryptography;

namespace Security.HMAC
{
    public class HmacOptions
    {
        public IAppSecretRepository AppSecretRepository { get; }
        
        public HmacSigningAlgorithm Algorithm { get; set; } = new HmacSigningAlgorithm(sb => new HMACSHA256(sb));
        public ITime Time { get; set; } = new SystemTime();
        public TimeSpan ClockSkew { get; set; } = TimeSpan.FromSeconds(30);
        public string RequestProtocol { get; set; }
        public string Host { get; set; }

        public HmacOptions(IAppSecretRepository appSecretRepository)
        {
            AppSecretRepository = appSecretRepository;
        }
    }
}