using System;
using System.Runtime.Versioning;
using mRemoteNG.Security;

namespace mRemoteNG.Connection.Credentials
{
    [SupportedOSPlatform("windows")]
    public sealed class EmptyCredentialsOptions
    {
        public string Mode { get; set; } = string.Empty;
        public string DefaultUsername { get; set; } = string.Empty;
        public string DefaultPassword { get; set; } = string.Empty;
        public string DefaultDomain { get; set; } = string.Empty;
        public string UserViaApiDefault { get; set; } = string.Empty;
        public ExternalCredentialProvider ExternalCredentialProviderDefault { get; set; }
        public string WindowsUserName { get; set; } = string.Empty;
        public string WindowsUserDomainName { get; set; } = string.Empty;

        public static EmptyCredentialsOptions FromSettings()
        {
            Properties.OptionsCredentialsPage settings = Properties.OptionsCredentialsPage.Default;
            return new EmptyCredentialsOptions
            {
                Mode = settings.EmptyCredentials ?? string.Empty,
                DefaultUsername = settings.DefaultUsername ?? string.Empty,
                DefaultPassword = string.IsNullOrEmpty(settings.DefaultPassword)
                    ? string.Empty
                    : OptionPasswords.Unprotect(settings.DefaultPassword),
                DefaultDomain = settings.DefaultDomain ?? string.Empty,
                UserViaApiDefault = settings.UserViaAPIDefault ?? string.Empty,
                ExternalCredentialProviderDefault = settings.ExternalCredentialProviderDefault,
                WindowsUserName = Environment.UserName,
                WindowsUserDomainName = Environment.UserDomainName
            };
        }
    }
}
