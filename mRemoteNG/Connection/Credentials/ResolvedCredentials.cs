namespace mRemoteNG.Connection.Credentials
{
    public sealed class ResolvedCredentials
    {
        public string Username { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
        public string Domain { get; set; } = string.Empty;
        public string PrivateKey { get; set; } = string.Empty;
        public bool SkipCredentials { get; set; }
    }
}
