using System.Collections.Generic;
using mRemoteNG.Connection;
using mRemoteNG.Connection.Credentials;
using mRemoteNG.Connection.Protocol.RDP;
using mRemoteNG.Messages;
using mRemoteNG.Security.WindowsCredentialManager;
using NSubstitute;
using NUnit.Framework;

namespace mRemoteNGTests.Connection.Credentials
{
    [TestFixture]
    public class ConnectionCredentialResolverTests
    {
        private IWindowsCredentialStore _credentialStore;
        private EmptyCredentialsOptions _emptyOptions;
        private ConnectionCredentialResolver _resolver;

        [SetUp]
        public void Setup()
        {
            _credentialStore = Substitute.For<IWindowsCredentialStore>();
            _emptyOptions = new EmptyCredentialsOptions
            {
                Mode = "noinfo",
                WindowsUserName = "winuser",
                WindowsUserDomainName = "WINDOMAIN"
            };
            _resolver = new ConnectionCredentialResolver(_credentialStore, () => _emptyOptions);
        }

        [Test]
        public void Resolve_WithNoCredentialsForceFlag_SkipsLookupAndSetsSkipCredentials()
        {
            ConnectionInfo info = new()
            {
                Hostname = "server01.corp.local",
                ExternalCredentialProvider = ExternalCredentialProvider.WindowsCredentialManager,
                UserViaAPI = "CORP/SharedAdmin"
            };

            ResolvedCredentials result = _resolver.Resolve(new CredentialResolutionRequest
            {
                ConnectionInfo = info,
                Force = ConnectionInfo.Force.NoCredentials,
                Target = ProtocolCredentialTarget.Rdp
            });

            Assert.That(result.SkipCredentials, Is.True);
            Assert.That(result.Username, Is.EqualTo(string.Empty));
            Assert.That(result.Password, Is.EqualTo(string.Empty));
            Assert.That(result.Domain, Is.EqualTo(string.Empty));
            _credentialStore.DidNotReceiveWithAnyArgs().TryRead(default, out _);
        }

        [TestCase(ProtocolCredentialTarget.Rdp)]
        [TestCase(ProtocolCredentialTarget.Ssh)]
        public void Resolve_WindowsCredentialManagerWithExplicitUserViaApi_ResolvesTargetCredentials(
            ProtocolCredentialTarget target)
        {
            ConnectionInfo info = new()
            {
                Hostname = "server01.corp.local",
                ExternalCredentialProvider = ExternalCredentialProvider.WindowsCredentialManager,
                UserViaAPI = "CORP/DomainAdmin"
            };

            _credentialStore.TryRead("CORP/DomainAdmin", out Arg.Any<WindowsCredential>())
                .Returns(callInfo =>
                {
                    callInfo[1] = new WindowsCredential
                    {
                        TargetName = "CORP/DomainAdmin",
                        Domain = "CORP",
                        Username = "admin",
                        Password = "secret-password",
                        Type = WindowsCredentialType.Generic
                    };
                    return true;
                });

            ResolvedCredentials result = _resolver.Resolve(new CredentialResolutionRequest
            {
                ConnectionInfo = info,
                Target = target
            });

            Assert.That(result.SkipCredentials, Is.False);
            Assert.That(result.Domain, Is.EqualTo("CORP"));
            Assert.That(result.Username, Is.EqualTo("admin"));
            Assert.That(result.Password, Is.EqualTo("secret-password"));
            _credentialStore.Received(1).TryRead("CORP/DomainAdmin", out Arg.Any<WindowsCredential>());
        }

        [Test]
        public void Resolve_WindowsCredentialManagerWithBlankUserViaApi_TriesTermsrvThenHostname()
        {
            ConnectionInfo info = new()
            {
                Hostname = "app01.corp.local",
                ExternalCredentialProvider = ExternalCredentialProvider.WindowsCredentialManager,
                UserViaAPI = string.Empty
            };

            _credentialStore.TryRead("TERMSRV/app01.corp.local", out Arg.Any<WindowsCredential>())
                .Returns(false);
            _credentialStore.TryRead("app01.corp.local", out Arg.Any<WindowsCredential>())
                .Returns(callInfo =>
                {
                    callInfo[1] = new WindowsCredential
                    {
                        TargetName = "app01.corp.local",
                        Domain = "CORP",
                        Username = "svc-rdp",
                        Password = "host-password",
                        Type = WindowsCredentialType.Generic
                    };
                    return true;
                });

            ResolvedCredentials result = _resolver.Resolve(new CredentialResolutionRequest
            {
                ConnectionInfo = info,
                Target = ProtocolCredentialTarget.Rdp
            });

            Assert.That(result.Domain, Is.EqualTo("CORP"));
            Assert.That(result.Username, Is.EqualTo("svc-rdp"));
            Assert.That(result.Password, Is.EqualTo("host-password"));
            Received.InOrder(() =>
            {
                _credentialStore.TryRead("TERMSRV/app01.corp.local", out Arg.Any<WindowsCredential>());
                _credentialStore.TryRead("app01.corp.local", out Arg.Any<WindowsCredential>());
            });
        }

        [Test]
        public void Resolve_WindowsCredentialManagerMissingEntry_LogsWarningAndDoesNotThrow()
        {
            ConnectionInfo info = new()
            {
                Hostname = "missing.corp.local",
                ExternalCredentialProvider = ExternalCredentialProvider.WindowsCredentialManager,
                UserViaAPI = "MissingTarget"
            };

            List<(MessageClass MsgClass, string Message)> logs = new();

            ResolvedCredentials result = _resolver.Resolve(new CredentialResolutionRequest
            {
                ConnectionInfo = info,
                Target = ProtocolCredentialTarget.Rdp,
                OnLog = (msgClass, msg) => logs.Add((msgClass, msg))
            });

            Assert.That(result.Username, Is.EqualTo(string.Empty));
            Assert.That(result.Password, Is.EqualTo(string.Empty));
            Assert.That(logs.Count, Is.EqualTo(1));
            Assert.That(logs[0].MsgClass, Is.EqualTo(MessageClass.WarningMsg));
            Assert.That(logs[0].Message, Does.Contain("MissingTarget"));
        }

        [Test]
        public void Resolve_EmptyCredentialsWindowsMode_FillsUsernameAndDomainWithoutPassword()
        {
            _emptyOptions = new EmptyCredentialsOptions
            {
                Mode = "windows",
                WindowsUserName = "jdoe",
                WindowsUserDomainName = "CORP"
            };

            ConnectionInfo info = new()
            {
                Hostname = "server01.corp.local",
                ExternalCredentialProvider = ExternalCredentialProvider.None
            };

            ResolvedCredentials result = _resolver.Resolve(new CredentialResolutionRequest
            {
                ConnectionInfo = info,
                Target = ProtocolCredentialTarget.Rdp
            });

            Assert.That(result.Username, Is.EqualTo("jdoe"));
            Assert.That(result.Domain, Is.EqualTo("CORP"));
            Assert.That(result.Password, Is.EqualTo(string.Empty));
        }

        [Test]
        public void Resolve_EmptyCredentialsCustomMode_FillsDefaultUsernamePasswordAndDomain()
        {
            _emptyOptions = new EmptyCredentialsOptions
            {
                Mode = "custom",
                DefaultUsername = "custom-user",
                DefaultPassword = "custom-password",
                DefaultDomain = "CUSTOMDOM"
            };

            ConnectionInfo info = new()
            {
                Hostname = "server01.corp.local",
                ExternalCredentialProvider = ExternalCredentialProvider.None
            };

            ResolvedCredentials result = _resolver.Resolve(new CredentialResolutionRequest
            {
                ConnectionInfo = info,
                Target = ProtocolCredentialTarget.Rdp
            });

            Assert.That(result.Username, Is.EqualTo("custom-user"));
            Assert.That(result.Password, Is.EqualTo("custom-password"));
            Assert.That(result.Domain, Is.EqualTo("CUSTOMDOM"));
        }

        [TestCase("CORP/GatewayCred", "CORP/GatewayCred")]
        [TestCase("", "TERMSRV/gw.corp.local")]
        public void Resolve_RdpGatewayTarget_ResolvesWindowsCredentialManagerViaUserViaApiOrTermsrvHostname(
            string gatewayUserViaApi,
            string expectedTarget)
        {
            ConnectionInfo info = new()
            {
                Hostname = "internal-host.corp.local",
                RDGatewayUsageMethod = RDGatewayUsageMethod.Always,
                RDGatewayUseConnectionCredentials = RDGatewayUseConnectionCredentials.ExternalCredentialProvider,
                RDGatewayExternalCredentialProvider = ExternalCredentialProvider.WindowsCredentialManager,
                RDGatewayHostname = "gw.corp.local",
                RDGatewayUserViaAPI = gatewayUserViaApi
            };

            _credentialStore.TryRead(expectedTarget, out Arg.Any<WindowsCredential>())
                .Returns(callInfo =>
                {
                    callInfo[1] = new WindowsCredential
                    {
                        TargetName = expectedTarget,
                        Domain = "GWDOM",
                        Username = "gwuser",
                        Password = "gwpassword",
                        Type = WindowsCredentialType.DomainPassword
                    };
                    return true;
                });

            ResolvedCredentials result = _resolver.Resolve(new CredentialResolutionRequest
            {
                ConnectionInfo = info,
                Target = ProtocolCredentialTarget.RdpGateway
            });

            Assert.That(result.Domain, Is.EqualTo("GWDOM"));
            Assert.That(result.Username, Is.EqualTo("gwuser"));
            Assert.That(result.Password, Is.EqualTo("gwpassword"));
            _credentialStore.Received(1).TryRead(expectedTarget, out Arg.Any<WindowsCredential>());
        }
    }
}
