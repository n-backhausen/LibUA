namespace LibUA
{
    namespace Core
    {
        /// <summary>
        /// The ApplicationType is an enumeration that specifies the type of OPC UA Application.
        /// </summary>
        public enum ApplicationType
        {
            /// <summary>
            /// The application is a Server.
            /// </summary>
            Server = 0,

            /// <summary>
            /// The application is a Client.
            /// </summary>
            Client = 1,

            /// <summary>
            /// The application is a Client and a Server.
            /// </summary>
            ClientAndServer = 2,

            /// <summary>
            /// The application is a DiscoveryServer.
            /// </summary>
            DiscoveryServer = 3,
        }
    }
}
