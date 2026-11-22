using mRemoteNG.Connection.Protocol.RDP;

namespace mRemoteNG.Security.WindowsCredentialManager
{
    public interface IWindowsCredentialStore
    {
        bool TryRead(string targetName, out WindowsCredential credential);

        ClearCachedCredentialsResult Delete(
            string targetName,
            WindowsCredentialType type = WindowsCredentialType.DomainPassword);
    }
}
