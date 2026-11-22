using System;
using System.Runtime.InteropServices;
using System.Text;
using mRemoteNG.Security.WindowsCredentialManager;
using NUnit.Framework;

namespace mRemoteNGTests.Security
{
    [TestFixture]
    public class WindowsCredentialManagerTests
    {
        [TestCase(@"CORP\jdoe", "CORP", "jdoe")]
        [TestCase(@"jdoe@corp.example.com", "", "jdoe@corp.example.com")]
        [TestCase("jdoe", "", "jdoe")]
        [TestCase("", "", "")]
        [TestCase(null, "", "")]
        [TestCase(@"CORP\sub\jdoe", "CORP", @"sub\jdoe")]
        public void SplitDomainAndUsername_ParsesExpectedParts(
            string rawUserName,
            string expectedDomain,
            string expectedUsername)
        {
            (string domain, string username) = WindowsCredentialManager.SplitDomainAndUsername(rawUserName);

            Assert.That(domain, Is.EqualTo(expectedDomain));
            Assert.That(username, Is.EqualTo(expectedUsername));
        }

        [Test]
        public void DecodeCredentialBlob_WithUtf16Bytes_ReturnsDecodedPassword()
        {
            const string secret = "P@ssw0rd!123";
            byte[] bytes = Encoding.Unicode.GetBytes(secret);
            IntPtr ptr = Marshal.AllocHGlobal(bytes.Length);
            try
            {
                Marshal.Copy(bytes, 0, ptr, bytes.Length);

                string decoded = WindowsCredentialManager.DecodeCredentialBlob(ptr, (uint)bytes.Length);

                Assert.That(decoded, Is.EqualTo(secret));
            }
            finally
            {
                Marshal.FreeHGlobal(ptr);
            }
        }

        [Test]
        public void DecodeCredentialBlob_WithZeroSizeOrNullPointer_ReturnsEmptyString()
        {
            Assert.That(WindowsCredentialManager.DecodeCredentialBlob(IntPtr.Zero, 10), Is.EqualTo(string.Empty));

            IntPtr ptr = Marshal.AllocHGlobal(4);
            try
            {
                Assert.That(WindowsCredentialManager.DecodeCredentialBlob(ptr, 0), Is.EqualTo(string.Empty));
            }
            finally
            {
                Marshal.FreeHGlobal(ptr);
            }
        }
    }
}
