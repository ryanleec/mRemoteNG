using System;
using mRemoteNG.Messages;

namespace mRemoteNG.Connection.Credentials
{
    public sealed class CredentialResolutionRequest
    {
        public ConnectionInfo ConnectionInfo { get; set; }
        public ConnectionInfo.Force Force { get; set; }
        public ProtocolCredentialTarget Target { get; set; }
        public ExternalConnectors.OP.OnePasswordRead OnePasswordReadAhead { get; set; }
        public Action<string> OnProviderError { get; set; }
        public Action<MessageClass, string> OnLog { get; set; }
    }
}
