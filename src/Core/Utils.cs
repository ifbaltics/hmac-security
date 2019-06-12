using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http.Headers;

namespace Security.HMAC
{
    internal static class Utils
    {
        public static string FirstOrDefault(this HttpRequestHeaders headers, string name)
        {
            if (false == headers.TryGetValues(name, out IEnumerable<string> values))
                return null;

            return values.FirstOrDefault();
        }

        public static string Required(this HttpRequestHeaders headers, string name)
        {
            string header = headers.FirstOrDefault(name);

            if (header == null)
                throw new HmacAuthenticationException($"Required header '{name}' is not present");

            return header;
        }
    }
}