namespace Security.HMAC
{
    public sealed class HmacAuthenticationResult
    {
        public readonly string AppId;

        internal HmacAuthenticationResult(string appId)
        {
            AppId = appId;
        }
    }
}