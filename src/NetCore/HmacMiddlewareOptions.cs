namespace Security.HMAC
{
    using System;

    public class HmacMiddlewareOptions
    {
        public TimeSpan ClockSkew { get; set; }
        public string RequestProtocol { get; set; }
        public string Host { get; set; }
    }
}