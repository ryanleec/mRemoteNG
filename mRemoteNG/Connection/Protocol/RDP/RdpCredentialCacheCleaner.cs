using System.Runtime.Versioning;
using mRemoteNG.Security.WindowsCredentialManager;

namespace mRemoteNG.Connection.Protocol.RDP
{
    /// <summary>
    /// Helper to remove a cached RDP credential (TERMSRV/&lt;hostname&gt;) from the Windows
    /// Credential Manager before initiating a connection.
    /// <para>
    /// Windows stores RDP credentials when the user ticks "Remember me" in the mstsc credential
    /// prompt. On subsequent RDP connections to the same host, Windows substitutes the cached
    /// credential for whatever the calling application supplies, which silently breaks
    /// password rotation or credential changes made inside mRemoteNG.
    /// </para>
    /// <para>
    /// Calling this helper before connecting removes the cached entry, so the credentials
    /// configured on the connection are used as-is. Behaviour is opt-in per connection.
    /// </para>
    /// </summary>
    public enum ClearCachedCredentialsResult
    {
        Deleted,
        NotFound,
        Failed,
    }

    [SupportedOSPlatform("windows")]
    internal static class RdpCredentialCacheCleaner
    {
        /// <summary>
        /// Removes the cached TERMSRV/&lt;hostname&gt; entry from the current user's Windows
        /// Credential Manager.
        /// </summary>
        /// <param name="hostname">Hostname or IP address used in the RDP connection.</param>
        /// <returns>Outcome of the deletion attempt.</returns>
        public static ClearCachedCredentialsResult ClearCachedCredentials(string hostname)
        {
            if (string.IsNullOrWhiteSpace(hostname))
                return ClearCachedCredentialsResult.Failed;

            return WindowsCredentialManager.Instance.Delete(
                "TERMSRV/" + hostname,
                WindowsCredentialType.DomainPassword);
        }
    }
}
