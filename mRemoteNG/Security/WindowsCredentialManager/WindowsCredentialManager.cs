using System;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Runtime.Versioning;
using System.Text;
using mRemoteNG.App;
using mRemoteNG.Connection.Protocol.RDP;
using mRemoteNG.Messages;

namespace mRemoteNG.Security.WindowsCredentialManager
{
    [SupportedOSPlatform("windows")]
    public sealed class WindowsCredentialManager : IWindowsCredentialStore
    {
        private const int ERROR_NOT_FOUND = 1168;

        public static WindowsCredentialManager Instance { get; } = new();

        [DllImport("Advapi32.dll", SetLastError = true, EntryPoint = "CredReadW", CharSet = CharSet.Unicode)]
        private static extern bool CredRead(
            string target,
            WindowsCredentialType type,
            int reservedFlag,
            out IntPtr credentialPtr);

        [DllImport("Advapi32.dll", SetLastError = true, EntryPoint = "CredFree")]
        private static extern void CredFree(IntPtr buffer);

        [DllImport("Advapi32.dll", SetLastError = true, EntryPoint = "CredDeleteW", CharSet = CharSet.Unicode)]
        private static extern bool CredDelete(
            string target,
            WindowsCredentialType type,
            int reservedFlag);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct NativeCredential
        {
            public uint Flags;
            public uint Type;
            public string TargetName;
            public string Comment;
            public FILETIME LastWritten;
            public uint CredentialBlobSize;
            public IntPtr CredentialBlob;
            public uint Persist;
            public uint AttributeCount;
            public IntPtr Attributes;
            public string TargetAlias;
            public string UserName;
        }

        public bool TryRead(string targetName, out WindowsCredential credential)
        {
            credential = null;
            if (string.IsNullOrWhiteSpace(targetName))
                return false;

            return TryReadInternal(targetName, WindowsCredentialType.DomainPassword, out credential)
                || TryReadInternal(targetName, WindowsCredentialType.Generic, out credential);
        }

        public ClearCachedCredentialsResult Delete(
            string targetName,
            WindowsCredentialType type = WindowsCredentialType.DomainPassword)
        {
            if (string.IsNullOrWhiteSpace(targetName))
                return ClearCachedCredentialsResult.Failed;

            try
            {
                bool deleted = CredDelete(targetName, type, 0);
                if (deleted)
                {
                    Runtime.MessageCollector.AddMessage(
                        MessageClass.InformationMsg,
                        $"Cleared cached RDP credentials for {targetName}.");
                    return ClearCachedCredentialsResult.Deleted;
                }

                int err = Marshal.GetLastWin32Error();
                if (err == ERROR_NOT_FOUND)
                {
                    return ClearCachedCredentialsResult.NotFound;
                }

                Runtime.MessageCollector.AddMessage(
                    MessageClass.WarningMsg,
                    $"CredDelete failed for {targetName} (Win32 error {err}).");
                return ClearCachedCredentialsResult.Failed;
            }
            catch (Exception ex)
            {
                Runtime.MessageCollector.AddExceptionStackTrace(
                    $"Failed to clear cached RDP credentials for {targetName}.",
                    ex);
                return ClearCachedCredentialsResult.Failed;
            }
        }

        private static bool TryReadInternal(
            string targetName,
            WindowsCredentialType type,
            out WindowsCredential credential)
        {
            credential = null;
            IntPtr credPtr = IntPtr.Zero;

            try
            {
                if (!CredRead(targetName, type, 0, out credPtr) || credPtr == IntPtr.Zero)
                    return false;

                NativeCredential nativeCred = Marshal.PtrToStructure<NativeCredential>(credPtr);
                (string domain, string username) = SplitDomainAndUsername(nativeCred.UserName);
                string password = DecodeCredentialBlob(nativeCred.CredentialBlob, nativeCred.CredentialBlobSize);

                credential = new WindowsCredential
                {
                    TargetName = nativeCred.TargetName ?? targetName,
                    Domain = domain,
                    Username = username,
                    Password = password,
                    Type = type
                };
                return true;
            }
            catch (Exception ex)
            {
                Runtime.MessageCollector.AddExceptionStackTrace(
                    $"Failed to read Windows Credential Manager entry '{targetName}'.",
                    ex);
                credential = null;
                return false;
            }
            finally
            {
                if (credPtr != IntPtr.Zero)
                    CredFree(credPtr);
            }
        }

        internal static string DecodeCredentialBlob(IntPtr blobPtr, uint blobSize)
        {
            if (blobPtr == IntPtr.Zero || blobSize == 0)
                return string.Empty;

            if (blobSize > int.MaxValue)
                return string.Empty;

            byte[] bytes = new byte[blobSize];
            try
            {
                Marshal.Copy(blobPtr, bytes, 0, (int)blobSize);
                return Encoding.Unicode.GetString(bytes);
            }
            finally
            {
                Array.Clear(bytes, 0, bytes.Length);
            }
        }

        internal static (string Domain, string Username) SplitDomainAndUsername(string rawUserName)
        {
            if (string.IsNullOrEmpty(rawUserName))
                return (string.Empty, string.Empty);

            int separatorIndex = rawUserName.IndexOf('\\');
            if (separatorIndex >= 0)
            {
                string domain = rawUserName.Substring(0, separatorIndex);
                string username = rawUserName.Substring(separatorIndex + 1);
                return (domain, username);
            }

            return (string.Empty, rawUserName);
        }
    }
}
