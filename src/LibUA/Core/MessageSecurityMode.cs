namespace LibUA
{
    namespace Core
    {
        /// <summary>
        /// The MessageSecurityMode is an enumeration that specifies what security should be applied to messages exchanges during a Session.
        /// </summary>
        public enum MessageSecurityMode
        {
            /// <summary>
            /// The MessageSecurityMode is invalid.
            /// </summary>
            Invalid = 0,

            /// <summary>
            /// No security is applied.
            /// </summary>
            None = 1,

            /// <summary>
            /// All messages are signed but not encrypted.
            /// </summary>
            Sign = 2,

            /// <summary>
            /// All messages are signed and encrypted.
            /// </summary>
            SignAndEncrypt = 3,
        }
    }
}
