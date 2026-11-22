namespace mRemoteNG.Security.WindowsCredentialManager
{
    public enum WindowsCredentialType : uint
    {
        Generic = 1,
        DomainPassword = 2,
        DomainCertificate = 3
    }

    public sealed class WindowsCredential
    {
        public string TargetName { get; set; } = string.Empty;
        public string Username { get; set; } = string.Empty;
        public string Domain { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
        public WindowsCredentialType Type { get; set; }
    }
}
