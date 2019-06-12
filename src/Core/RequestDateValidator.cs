using System;

namespace Security.HMAC
{
    public interface IHmacRequestDateValidator
    {
        void Validate(DateTimeOffset requestDate);
    }

    public class HmacRequestDateValidator : IHmacRequestDateValidator
    {
        private readonly ITime timeProvider;
        private readonly TimeSpan clockSkew;

        public HmacRequestDateValidator(ITime timeProvider, TimeSpan clockSkew)
        {
            this.timeProvider = timeProvider;
            this.clockSkew = clockSkew;
        }

        public void Validate(DateTimeOffset requestDate)
        {
            DateTimeOffset currentDate = timeProvider.UtcNow;
            TimeSpan diff = currentDate.Subtract(requestDate);

            if (Math.Abs(diff.TotalSeconds) > clockSkew.TotalSeconds)
                throw new HmacAuthenticationException($"Request date mismatch. Request date: '{requestDate:R}', Current date: '{currentDate:R}'");
        }
    }
}