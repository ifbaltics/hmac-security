using System;

namespace Security.HMAC
{
    public class HmacAuthenticationException : Exception
    {
        internal HmacAuthenticationException(string msg) : base(msg)
        {
        }
    }
}