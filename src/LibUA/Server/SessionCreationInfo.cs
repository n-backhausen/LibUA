using System.Net;

namespace LibUA
{
    namespace Server
    {
        /// <summary>
        /// Information about the session that will be created.
        /// </summary>
        public struct SessionCreationInfo
        {
            /// <summary>
            /// Remote endpoint.
            /// </summary>
            public EndPoint Endpoint;
        }
    }
}
