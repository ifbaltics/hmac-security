using System;

namespace Security.HMAC
{
    public interface ITime
    {
        DateTimeOffset UtcNow { get; }
    }

    public class SystemTime : ITime
    {
        public static readonly ITime Instance = new SystemTime();

        public DateTimeOffset UtcNow => DateTimeOffset.UtcNow;
    }
}
