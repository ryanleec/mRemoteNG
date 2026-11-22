using System;
using System.Collections.Generic;
using System.Runtime.Versioning;
using mRemoteNG.App;
using mRemoteNG.Connection.Protocol.RDP;
using mRemoteNG.Messages;
using mRemoteNG.Resources.Language;
using mRemoteNG.Security.WindowsCredentialManager;

namespace mRemoteNG.Connection.Credentials
{
    [SupportedOSPlatform("windows")]
    public sealed class ConnectionCredentialResolver : ICredentialResolver
    {
        private readonly IWindowsCredentialStore _windowsCredentialStore;
        private readonly Func<EmptyCredentialsOptions> _emptyCredentialsProvider;

        public ConnectionCredentialResolver(
            IWindowsCredentialStore windowsCredentialStore,
            Func<EmptyCredentialsOptions> emptyCredentialsProvider = null)
        {
            _windowsCredentialStore = windowsCredentialStore
                ?? throw new ArgumentNullException(nameof(windowsCredentialStore));
            _emptyCredentialsProvider = emptyCredentialsProvider ?? EmptyCredentialsOptions.FromSettings;
        }

        public ResolvedCredentials Resolve(CredentialResolutionRequest request)
        {
            if (request == null)
                throw new ArgumentNullException(nameof(request));

            if (request.Force.HasFlag(ConnectionInfo.Force.NoCredentials))
                return new ResolvedCredentials { SkipCredentials = true };

            ConnectionInfo info = request.ConnectionInfo;
            Action<MessageClass, string> log = request.OnLog
                ?? ((msgClass, message) => Runtime.MessageCollector.AddMessage(msgClass, message));
            Action<string> reportError = request.OnProviderError
                ?? (message => log(MessageClass.ErrorMsg, message));

            ExtractInitialFields(
                info,
                request.Target,
                out string username,
                out string password,
                out string domain,
                out string userViaApi,
                out ExternalCredentialProvider provider,
                out string hostname);

            string privateKey = string.Empty;

            ResolveFromExternalProvider(
                info,
                request.Target,
                provider,
                userViaApi,
                hostname,
                request.OnePasswordReadAhead,
                ref username,
                ref password,
                ref domain,
                ref privateKey,
                log,
                reportError);

            if (request.Target != ProtocolCredentialTarget.RdpGateway)
            {
                ApplyEmptyCredentialsFallback(
                    request.Target,
                    ref username,
                    ref password,
                    ref domain,
                    ref privateKey,
                    reportError);
            }

            return new ResolvedCredentials
            {
                Username = username ?? string.Empty,
                Password = password ?? string.Empty,
                Domain = domain ?? string.Empty,
                PrivateKey = privateKey ?? string.Empty,
                SkipCredentials = false
            };
        }

        private static void ExtractInitialFields(
            ConnectionInfo info,
            ProtocolCredentialTarget target,
            out string username,
            out string password,
            out string domain,
            out string userViaApi,
            out ExternalCredentialProvider provider,
            out string hostname)
        {
            if (target == ProtocolCredentialTarget.RdpGateway)
            {
                username = info?.RDGatewayUsername ?? string.Empty;
                password = info?.RDGatewayPassword ?? string.Empty;
                domain = info?.RDGatewayDomain ?? string.Empty;
                userViaApi = info?.RDGatewayUserViaAPI ?? string.Empty;
                provider = info != null
                    ? RdpProtocol.GatewayCredentialProvider(info)
                    : ExternalCredentialProvider.None;
                hostname = info?.RDGatewayHostname ?? string.Empty;
                return;
            }

            username = info?.Username ?? string.Empty;
            password = info?.Password ?? string.Empty;
            domain = info?.Domain ?? string.Empty;
            userViaApi = info?.UserViaAPI ?? string.Empty;
            provider = info?.ExternalCredentialProvider ?? ExternalCredentialProvider.None;
            hostname = info?.Hostname ?? string.Empty;
        }

        private void ResolveFromExternalProvider(
            ConnectionInfo info,
            ProtocolCredentialTarget target,
            ExternalCredentialProvider provider,
            string userViaApi,
            string hostname,
            ExternalConnectors.OP.OnePasswordRead onePasswordReadAhead,
            ref string username,
            ref string password,
            ref string domain,
            ref string privateKey,
            Action<MessageClass, string> log,
            Action<string> reportError)
        {
            switch (provider)
            {
                case ExternalCredentialProvider.DelineaSecretServer:
                    try
                    {
                        ExternalConnectors.DSS.SecretServerInterface.FetchSecretFromServer(
                            $"{userViaApi}",
                            out username,
                            out password,
                            out domain,
                            out privateKey);
                    }
                    catch (Exception ex)
                    {
                        reportError("Secret Server Interface Error: " + ex.Message);
                    }
                    break;

                case ExternalCredentialProvider.ClickstudiosPasswordState:
                    try
                    {
                        ExternalConnectors.CPS.PasswordstateInterface.FetchSecretFromServer(
                            $"{userViaApi}",
                            out username,
                            out password,
                            out domain,
                            out privateKey);
                    }
                    catch (Exception ex)
                    {
                        reportError("Passwordstate Interface Error: " + ex.Message);
                    }
                    break;

                case ExternalCredentialProvider.OnePassword:
                    try
                    {
                        ExternalConnectors.OP.OnePasswordCli.ReadPassword(
                            onePasswordReadAhead,
                            $"{userViaApi}",
                            ref username,
                            ref password,
                            ref domain,
                            ref privateKey);
                    }
                    catch (ExternalConnectors.OP.OnePasswordCliException ex)
                    {
                        log(MessageClass.InformationMsg, Language.ECPOnePasswordCommandLine + ": " + ex.Arguments);
                        log(MessageClass.ErrorMsg, Language.ECPOnePasswordReadFailed + Environment.NewLine + ex.Message);
                    }
                    catch (Exception ex)
                    {
                        log(MessageClass.ErrorMsg, Language.ECPOnePasswordReadFailed + Environment.NewLine + ex.Message);
                    }
                    break;

                case ExternalCredentialProvider.VaultOpenbao:
                    ResolveFromVaultOpenbao(info, target, ref username, out password, reportError);
                    break;

                case ExternalCredentialProvider.WindowsCredentialManager:
                    ResolveFromWindowsCredentialManager(
                        userViaApi,
                        hostname,
                        ref username,
                        ref password,
                        ref domain,
                        log);
                    break;
            }
        }

        private static void ResolveFromVaultOpenbao(
            ConnectionInfo info,
            ProtocolCredentialTarget target,
            ref string username,
            out string password,
            Action<string> reportError)
        {
            password = string.Empty;
            if (info == null)
                return;

            try
            {
                if (target == ProtocolCredentialTarget.Ssh)
                {
                    if (info.VaultOpenbaoSecretEngine == VaultOpenbaoSecretEngine.SSHOTP)
                    {
                        ExternalConnectors.VO.VaultOpenbao.ReadOtpSSH(
                            $"{info.VaultOpenbaoMount}",
                            $"{info.VaultOpenbaoRole}",
                            $"{info.Username}",
                            $"{info.Hostname}",
                            out password);
                    }
                    else
                    {
                        ExternalConnectors.VO.VaultOpenbao.ReadPasswordSSH(
                            (int)info.VaultOpenbaoSecretEngine,
                            info.VaultOpenbaoMount ?? string.Empty,
                            info.VaultOpenbaoRole ?? string.Empty,
                            info.Username ?? "root",
                            out password);
                    }
                    return;
                }

                if (info.VaultOpenbaoSecretEngine == VaultOpenbaoSecretEngine.Kv)
                {
                    username = target == ProtocolCredentialTarget.RdpGateway
                        ? info.RDGatewayUsername ?? string.Empty
                        : info.Username ?? string.Empty;
                }

                ExternalConnectors.VO.VaultOpenbao.ReadPasswordRDP(
                    (int)info.VaultOpenbaoSecretEngine,
                    info.VaultOpenbaoMount ?? string.Empty,
                    info.VaultOpenbaoRole ?? string.Empty,
                    ref username,
                    out password);
            }
            catch (ExternalConnectors.VO.VaultOpenbaoException ex)
            {
                reportError("Secret Server Interface Error: " + ex.Message);
            }
        }

        private void ResolveFromWindowsCredentialManager(
            string userViaApi,
            string hostname,
            ref string username,
            ref string password,
            ref string domain,
            Action<MessageClass, string> log)
        {
            List<string> candidates = BuildWindowsCredentialTargets(userViaApi, hostname);
            foreach (string candidate in candidates)
            {
                if (_windowsCredentialStore.TryRead(candidate, out WindowsCredential credential) && credential != null)
                {
                    if (!string.IsNullOrEmpty(credential.Username))
                        username = credential.Username;
                    if (!string.IsNullOrEmpty(credential.Password))
                        password = credential.Password;
                    if (!string.IsNullOrEmpty(credential.Domain))
                        domain = credential.Domain;
                    return;
                }
            }

            string targets = candidates.Count > 0 ? string.Join(", ", candidates) : string.Empty;
            log(MessageClass.WarningMsg, string.Format(Language.ECPWindowsCredentialManagerNotFound, targets));
        }

        private static List<string> BuildWindowsCredentialTargets(string userViaApi, string hostname)
        {
            List<string> candidates = new();
            if (!string.IsNullOrWhiteSpace(userViaApi))
            {
                candidates.Add(userViaApi.Trim());
            }
            else if (!string.IsNullOrWhiteSpace(hostname))
            {
                string trimmedHost = hostname.Trim();
                candidates.Add("TERMSRV/" + trimmedHost);
                candidates.Add(trimmedHost);
            }

            return candidates;
        }

        private void ApplyEmptyCredentialsFallback(
            ProtocolCredentialTarget target,
            ref string username,
            ref string password,
            ref string domain,
            ref string privateKey,
            Action<string> reportError)
        {
            EmptyCredentialsOptions options = _emptyCredentialsProvider() ?? new EmptyCredentialsOptions();

            if (string.IsNullOrEmpty(username))
            {
                switch (options.Mode)
                {
                    case "windows":
                        username = options.WindowsUserName ?? string.Empty;
                        break;

                    case "custom" when !string.IsNullOrEmpty(options.DefaultUsername):
                        username = options.DefaultUsername;
                        break;

                    case "custom":
                        if (target != ProtocolCredentialTarget.Ssh ||
                            options.ExternalCredentialProviderDefault == ExternalCredentialProvider.DelineaSecretServer)
                        {
                            try
                            {
                                ExternalConnectors.DSS.SecretServerInterface.FetchSecretFromServer(
                                    $"{options.UserViaApiDefault}",
                                    out username,
                                    out password,
                                    out domain,
                                    out privateKey);
                            }
                            catch (Exception ex)
                            {
                                reportError("Secret Server Interface Error: " + ex.Message);
                            }
                        }
                        break;
                }
            }

            if (target == ProtocolCredentialTarget.Rdp)
            {
                if (string.IsNullOrEmpty(password) &&
                    options.Mode == "custom" &&
                    !string.IsNullOrEmpty(options.DefaultPassword))
                {
                    password = options.DefaultPassword;
                }

                if (string.IsNullOrEmpty(domain))
                {
                    domain = options.Mode switch
                    {
                        "windows" => options.WindowsUserDomainName ?? string.Empty,
                        "custom" => options.DefaultDomain ?? string.Empty,
                        _ => domain
                    };
                }
            }
        }
    }
}
