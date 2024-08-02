using System;

namespace LibUA
{
    namespace Core
    {
        /// <summary>
        /// Indicate how the Value of a Variable can be accessed (read/write) and if it contains current and/or historic data.
        /// </summary>
        [Flags]
        public enum AccessLevel
        {
            /// <summary>
            /// Indicates if the current value is readable. It also indicates if the current value of the Variable is available.
            /// </summary>
            CurrentRead = 0x1,

            /// <summary>
            /// Indicates if the current value is writable. It also indicates if the current value of the Variable is available.
            /// </summary>
            CurrentWrite = 0x2,

            /// <summary>
            /// Indicates if the history of the value is readable. It also indicates if the history of the Variable is available via the OPC UA Server.
            /// </summary>
            HistoryRead = 0x4,

            /// <summary>
            /// Indicates if the history of the value is writable It also indicates if the history of the Variable is available via the OPC UA Server.
            /// </summary>
            HistoryWrite = 0x8,
        }
    }
}
