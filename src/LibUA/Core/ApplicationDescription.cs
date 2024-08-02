using System.IO;

namespace LibUA
{
    namespace Core
    {
        /// <summary>
        /// Specifies an application that is available.
        /// </summary>
        public class ApplicationDescription
        {
            /// <summary>
            /// The globally unique identifier for the application instance.
            /// </summary>
            public string ApplicationUri
            {
                get; protected set;
            }

            /// <summary>
            /// The globally unique identifier for the product.
            /// </summary>
            public string ProductUri
            {
                get; protected set;
            }

            /// <summary>
            /// A localized descriptive name for the application.
            /// </summary>
            public LocalizedText ApplicationName
            {
                get; protected set;
            }

            /// <summary>
            /// The type of application.
            /// </summary>
            public ApplicationType Type
            {
                get; protected set;
            }

            /// <summary>
            /// A URI that identifies the Gateway Server associated with the discoveryUrls. This value is not specified if the Server can be accessed directly.
            /// </summary>
            public string GatewayServerUri
            {
                get; protected set;
            }

            /// <summary>
            /// A URI that identifies the discovery profile supported by the URLs provided. If this value is not specified then the Endpoints shall support the Discovery Services.
            /// </summary>
            public string DiscoveryProfileUri
            {
                get; protected set;
            }

            /// <summary>
            /// A list of URLs for the DiscoveryEndpoints provided by the application.
            /// </summary>
            public string[] DiscoveryUrls
            {
                get; protected set;
            }

            /// <summary>
            /// Initializes the instance.
            /// </summary>
            public ApplicationDescription(string ApplicationUri, string ProductUri, LocalizedText ApplicationName, ApplicationType Type, string GatewayServerUri, string DiscoveryProfileUri, string[] DiscoveryUrls)
            {
                this.ApplicationUri = ApplicationUri;
                this.ProductUri = ProductUri;
                this.ApplicationName = ApplicationName;
                this.Type = Type;
                this.GatewayServerUri = GatewayServerUri;
                this.DiscoveryProfileUri = DiscoveryProfileUri;
                this.DiscoveryUrls = DiscoveryUrls;
            }
        }
    }
}
