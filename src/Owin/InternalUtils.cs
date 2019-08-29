using System.Collections.Generic;
using System.Linq;
using Microsoft.Owin;

namespace Security.HMAC
{
    internal static class InternalUtils
    {
        public static HmacRequestInfo ToRequestInfo(this IOwinRequest request)
        {
             return new HmacRequestInfo(
                 request.Method, 
                 request.Uri, 
                 request.Headers.Select(p => new KeyValuePair<string,string>(p.Key, p.Value.First())).ToList());
        }
    }
}