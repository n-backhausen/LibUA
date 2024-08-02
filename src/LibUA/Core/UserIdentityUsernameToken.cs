namespace LibUA
{
    namespace Core
    {
        public class UserIdentityUsernameToken : UserIdentityToken
        {
            public string Username { get; protected set; }
            public byte[] PasswordHash { get; protected set; }
            public string Algorithm { get; protected set; }

            public UserIdentityUsernameToken(string PolicyId, string Username, byte[] PasswordHash, string Algorithm)
            {
                this.PolicyId = PolicyId;
                this.Username = Username;
                this.PasswordHash = PasswordHash;
                this.Algorithm = Algorithm;
            }
        }
    }
}
