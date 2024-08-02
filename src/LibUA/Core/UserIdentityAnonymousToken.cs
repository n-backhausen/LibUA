namespace LibUA
{
    namespace Core
    {
        /// <summary>
        /// Represent an anonymous user identity token.
        /// </summary>
        public class UserIdentityAnonymousToken : UserIdentityToken
        {
            /// <summary>
            /// Initializes the instance.
            /// </summary>
            /// <param name="PolicyId"></param>
            public UserIdentityAnonymousToken(string PolicyId)
            {
                this.PolicyId = PolicyId;
            }
        }
    }
}
