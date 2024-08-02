namespace LibUA.Core
{
    /// <summary>
    /// Base class for user identity token.
    /// </summary>
    public abstract class UserIdentityToken
    {
        /// <summary>
        /// An identifier for the UserTokenPolicy assigned by the Server. The Client specifies this value when it constructs a UserIdentityToken that conforms to the policy.
        /// </summary>
        public string PolicyId { get; protected set; }
    }
}