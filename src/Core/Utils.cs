using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;

namespace Security.HMAC
{
    internal static class Utils
    {
        public static string FirstOrDefault(this IEnumerable<KeyValuePair<string, string>> headers, string name)
        {
            return headers.FirstOrDefault(p => p.Key.Equals(name, StringComparison.OrdinalIgnoreCase)).Value;
        }

        public static string Required(this IEnumerable<KeyValuePair<string, string>> headers, string name)
        {
            string header = headers.FirstOrDefault(name);

            if (header == null)
                throw new HmacAuthenticationException($"Required header '{name}' is not present");

            return header;
        }

        public static IEnumerable<string> All(this IEnumerable<KeyValuePair<string, string>> headers, string name)
        {
            foreach (var h in headers)
                if (h.Key.Equals(name, StringComparison.OrdinalIgnoreCase))
                    yield return h.Value;
        }

        public static HmacRequestInfo ToRequestInfo(this HttpRequestMessage msg)
        {
            return new HmacRequestInfo(
                msg.Method.Method, 
                msg.RequestUri, 
                msg.Headers.Select(p => new KeyValuePair<string,string>(p.Key, p.Value.First())).ToList());
        }
    }
}