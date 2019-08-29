using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;

namespace Security.HMAC
{
    internal static class InternalUtils
    {
        public static HmacRequestInfo ToRequestInfo(this HttpRequest request)
        {
            return new HmacRequestInfo(
                request.Method, 
                new Uri(request.GetEncodedUrl()), 
                request.Headers.Select(p => new KeyValuePair<string, string>(p.Key, p.Value)).ToList());
        }

    }
}