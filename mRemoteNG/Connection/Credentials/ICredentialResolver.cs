namespace mRemoteNG.Connection.Credentials
{
    public interface ICredentialResolver
    {
        ResolvedCredentials Resolve(CredentialResolutionRequest request);
    }
}
