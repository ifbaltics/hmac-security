using System;

namespace Security.HMAC
{
    public class HmacSignatureContent
    {
        public string Nonce;
        public string AppId;
        public string Method;
        public string ContentType;
        public string Accepts;
        public byte[] ContentMd5;
        public DateTimeOffset Date;
        public Uri Uri;

        public string ToCanonicalString()
        {
            string[] content =
            {
                Nonce,
                AppId,
                Method,
                ContentType,
                Accepts,
                Date.ToString("R"),
                Uri.GetComponents(UriComponents.AbsoluteUri, UriFormat.Unescaped).ToLowerInvariant()
            };

            var rep = string.Join("|", content);

            if ((ContentMd5?.Length ?? 0) != 0)
            {
                string md5 = Convert.ToBase64String(ContentMd5);
                rep += $"|{md5}";
            }

            return rep;
        }
    }
}