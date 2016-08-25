﻿namespace Security.HMAC
{
    using System;
    using Microsoft.Owin.Security;

    public class HmacAuthenticationOptions : AuthenticationOptions
    {
        public HmacAuthenticationOptions(ISigningAlgorithm algorithm, IAppSecretRepository appSecretRepository)
            : base(Schemas.HMAC)
        {
            Algorithm = algorithm;
            AppSecretRepository = appSecretRepository;
        }

        public ISigningAlgorithm Algorithm { get; set; }
        public IAppSecretRepository AppSecretRepository { get; set; }
        public ITime Time { get; set; } = SystemTime.Instance;
        public TimeSpan Tolerance { get; set; } = Constants.DefaultTolerance;
        public MapUserClaimsDelegate MapClaims { get; set; }
    }
}