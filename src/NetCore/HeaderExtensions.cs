namespace Security.HMAC
{
    using Microsoft.AspNetCore.Http;
    using Microsoft.Extensions.Primitives;

    public static class HeaderExtensions
    {
        public static StringValues? Get(this IHeaderDictionary headers, string key)
        {
            return headers.TryGetValue(key, out var value)
                ? value[0]
                : null;
        }

        public static bool Contains(this IHeaderDictionary headers, string key)
        {
            return headers.TryGetValue(key, out var value);
        }
    }
}