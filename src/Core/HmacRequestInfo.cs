using System;
using System.Collections.Generic;

namespace Security.HMAC
{
    public class HmacRequestInfo
    {
        public readonly string Method;
        public readonly Uri Url;
        public readonly ICollection<KeyValuePair<string, string>> Headers;
        
        public HmacRequestInfo(string method, Uri url, ICollection<KeyValuePair<string, string>> headers)
        {
            Method = method.ToUpperInvariant();
            Url = url;
            Headers = headers;
        }
    }
}