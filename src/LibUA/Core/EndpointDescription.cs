namespace LibUA
{
    namespace Core
    {
        /// <summary>
        /// Describes an Endpoint for a Server.
        /// </summary>
        public class EndpointDescription
        {
            /// <summary>
            /// The URL for the Endpoint described.
            /// </summary>
            public string EndpointUrl
            {
                get; protected set;
            }

            /// <summary>
            /// The description for the Server that the Endpoint belongs to.
            /// </summary>
            public ApplicationDescription Server
            {
                get; protected set;
            }

            /// <summary>
            /// The Application Instance Certificate issued to the Server.
            /// </summary>
            public byte[] ServerCertificate
            {
                get; protected set;
            }

            /// <summary>
            /// The type of security to apply to the messages.
            /// </summary>
            public MessageSecurityMode SecurityMode
            {
                get; protected set;
            }

            /// <summary>
            /// The URI for SecurityPolicy to use when securing messages.
            /// </summary>
            /// <remarks>
            /// The set of known URIs and the SecurityPolicies associated with them are defined in OPC 10000-7.
            /// </remarks>
            public string SecurityPolicyUri
            {
                get; protected set;
            }

            /// <summary>
            /// The user identity tokens that the Server will accept.
            /// </summary>
            public UserTokenPolicy[] UserIdentityTokens
            {
                get; protected set;
            }

            /// <summary>
            /// The URI of the Transport Profile supported by the Endpoint.
            /// </summary>
            /// <remarks>
            /// OPC 10000-7 defines URIs for the Transport Profiles.
            /// </remarks>
            public string TransportProfileUri
            {
                get; protected set;
            }

            /// <summary>
            /// A numeric value that indicates how secure the EndpointDescription is compared to other EndpointDescriptions for the same Server.
            /// </summary>
            /// <remarks>
            /// A value of 0 indicates that the EndpointDescription is not recommended and is only supported for backward compatibility.
            /// A higher value indicates better security.
            /// </remarks>
            public byte SecurityLevel
            {
                get; protected set;
            }

            /// <summary>
            /// Initializes the instance.
            /// </summary>
            public EndpointDescription(string EndpointUrl, ApplicationDescription Server, byte[] ServerCertificate, MessageSecurityMode SecurityMode, string SecurityPolicyUri, UserTokenPolicy[] UserIdentityTokens, string TransportProfileUri, byte SecurityLevel)
            {
                this.EndpointUrl = EndpointUrl;
                this.Server = Server;
                this.ServerCertificate = ServerCertificate;
                this.SecurityMode = SecurityMode;
                this.SecurityPolicyUri = SecurityPolicyUri;
                this.UserIdentityTokens = UserIdentityTokens;
                this.TransportProfileUri = TransportProfileUri;
                this.SecurityLevel = SecurityLevel;
            }
        }
    }
}
