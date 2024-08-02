using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using LibUA.Core;

namespace LibUA
{
    namespace Server
    {
        /// <summary>
        /// Base class for OPC UA server applications.
        /// </summary>
        public abstract partial class Application
        {
            /// <summary>
            /// Server internal key to identify monitored items.
            /// </summary>
            protected struct ServerMonitorKey : IEquatable<ServerMonitorKey>
            {
                /// <summary>
                /// Initializes the instance.
                /// </summary>
                public ServerMonitorKey(NodeId nodeId, NodeAttribute attribute)
                {
                    this.NodeId = nodeId;
                    this.Attribute = attribute;
                }

                /// <summary>
                /// Initializes the instance.
                /// </summary>
                /// <param name="itemToMonitor"></param>
                public ServerMonitorKey(ReadValueId itemToMonitor)
                    : this(itemToMonitor.NodeId, itemToMonitor.AttributeId)
                {
                }

                /// <summary>
                /// Node id.
                /// </summary>
                public NodeId NodeId;

                /// <summary>
                /// Node attribute.
                /// </summary>
                public NodeAttribute Attribute;

                /// <inheritdoc/>
                public override int GetHashCode()
                {
                    var h1 = NodeId.GetHashCode();

                    return ((h1 << 5) + h1) ^ Attribute.GetHashCode();
                }

                /// <inheritdoc/>
                public override bool Equals(object obj)
                {
                    if (obj is ServerMonitorKey)
                    {
                        return NodeId == ((ServerMonitorKey)obj).NodeId &&
                            Attribute == ((ServerMonitorKey)obj).Attribute;
                    }

                    return false;
                }

                /// <inheritdoc/>
                public bool Equals(ServerMonitorKey other)
                {
                    return NodeId.Equals(other.NodeId) && Attribute == other.Attribute;
                }
            }

            private HashSet<NodeId> internalAddressSpaceNodes;
            private Dictionary<NodeId, object> internalAddressSpaceValues;

            private readonly ReaderWriterLockSlim monitorMapRW;
            private readonly Dictionary<ServerMonitorKey, List<MonitoredItem>> monitorMap;

            /// <summary>
            /// Override in derived class, to provide the application certificate.
            /// </summary>
            public abstract X509Certificate2 ApplicationCertificate
            {
                get;
            }

            /// <summary>
            /// Override in derived class, to provide the private key of the application certificate.
            /// </summary>
            public abstract RSA ApplicationPrivateKey
            {
                get;
            }

            /// <summary>
            /// Flat register containing all known nodes for lookup operations.
            /// </summary>
            protected ConcurrentDictionary<NodeId, Node> AddressSpaceTable
            { 
                get; 
            }

            /// <summary>
            /// Initializes the instance.
            /// </summary>
            protected Application()
            {
                AddressSpaceTable = new ConcurrentDictionary<NodeId, Node>();

                SetupDefaultAddressSpace();

                // Missing in the auto-generated UA specification
                // BaseDataType organizes DataTypesFolder
                AddressSpaceTable[new NodeId(UAConst.BaseDataType)].References.Add(new ReferenceNode(new NodeId(UAConst.Organizes), new NodeId(UAConst.DataTypesFolder), false));

                SetupInternalAddressSpace();

                monitorMapRW = new ReaderWriterLockSlim();
                monitorMap = new Dictionary<ServerMonitorKey, List<MonitoredItem>>();
            }

            /// <summary>
            /// Gets the OPC UA application description.
            /// </summary>
            /// <param name="endpointUrlHint">The network address that the Client used to access the DiscoveryEndpoint.</param>
            /// <returns></returns>
            public abstract Core.ApplicationDescription GetApplicationDescription(string endpointUrlHint);

            /// <summary>
            /// Gets the Endpoints supported by the application and all of the configuration information required to establish a SecureChannel and a Session.
            /// </summary>
            /// <param name="endpointUrlHint">The network address that the Client used to access the DiscoveryEndpoint.</param>
            /// <returns>When inplemented in deriving class then this method should return descriptions of all accepted configurations for the endpoint.</returns>
            public abstract IList<Core.EndpointDescription> GetEndpointDescriptions(string endpointUrlHint);

            /// <summary>
            /// Adds a item to the monitor map.
            /// </summary>
            /// <param name="session">Session handle returned by the SessionCreate method.</param>
            /// <param name="mi">Monitored item handle. Contains a reference to the node.</param>
            /// <returns>Returns true when the item was added to the map. False is returned, when node was not found or the session has no read permission to the references node.</returns>
            public virtual bool MonitorAdd(object session, MonitoredItem mi)
            {
                if (!AddressSpaceTable.TryGetValue(mi.ItemToMonitor.NodeId, out _) ||
                    !SessionHasPermissionToRead(session, mi.ItemToMonitor.NodeId))
                {
                    return false;
                }

                var key = new ServerMonitorKey(mi.ItemToMonitor);

                try
                {
                    monitorMapRW.EnterWriteLock();

                    if (monitorMap.TryGetValue(key, out List<MonitoredItem> mis))
                    {
                        mis.Add(mi);
                    }
                    else
                    {
                        mis = new List<MonitoredItem>();
                        mis.Add(mi);
                        monitorMap.Add(key, mis);
                    }
                }
                finally
                {
                    monitorMapRW.ExitWriteLock();
                }

                return true;
            }

            /// <summary>
            /// Removes a item from monitoring map.
            /// </summary>
            /// <param name="session">Session handle returned by the SessionCreate method.</param>
            /// <param name="mi">Monitored item handle. Contains a reference to the node.</param>
            public virtual void MonitorRemove(object session, MonitoredItem mi)
            {
                var key = new ServerMonitorKey(mi.ItemToMonitor);
                try
                {
                    monitorMapRW.EnterWriteLock();
                    if (monitorMap.TryGetValue(key, out List<MonitoredItem> mis))
                    {
                        mis.Remove(mi);
                    }
                }
                finally
                {
                    monitorMapRW.ExitWriteLock();
                }
            }

            /// <summary>
            /// Queues a data change notification to be send to subscribers when node is monitored.
            /// </summary>
            /// <param name="id">Node id of the changed node.</param>
            /// <param name="dv">New value of the node.</param>
            /// <param name="filterHandler">Callback to determine if the MonitoredItem should generate a Notification.</param>
            public virtual void MonitorNotifyDataChange(NodeId id, DataValue dv, Predicate<MonitoringFilter> filterHandler = null)
            {
                var key = new ServerMonitorKey(id, NodeAttribute.Value);
                // Console.WriteLine("{0} {1}", id.ToString(), dv.Value.ToString());

                try
                {
                    monitorMapRW.EnterReadLock();
                    if (monitorMap.TryGetValue(key, out List<MonitoredItem> mis))
                    {
                        foreach (MonitoredItem mi in mis)
                        {
                            if (!(filterHandler?.Invoke(mi.Parameters?.Filter) ?? true))
                            {
                                continue;
                            }

                            if (mi.QueueData.Count >= mi.QueueSize)
                            {
                                mi.QueueOverflowed = true;
                            }
                            else
                            {
                                mi.QueueData.Enqueue(dv);
                            }

                            if (mi.ParentSubscription.ChangeNotification == Subscription.ChangeNotificationType.None)
                            {
                                mi.ParentSubscription.ChangeNotification = Subscription.ChangeNotificationType.AtPublish;
                            }
                        }
                    }
                }
                finally
                {
                    monitorMapRW.ExitReadLock();
                }
            }

            /// <summary>
            /// Queues a event notification to be send to subscribers when node is monitored.
            /// </summary>
            /// <param name="id">Node id of the changed node.</param>
            /// <param name="ev">Event information of the node.</param>
            /// <param name="filterHandler">Callback to determine if the MonitoredItem should generate a Notification.</param>
            public virtual void MonitorNotifyEvent(NodeId id, EventNotification ev, Predicate<MonitoringFilter> filterHandler = null)
            {
                var key = new ServerMonitorKey(id, NodeAttribute.EventNotifier);
                //Console.WriteLine("{0} {1}", id.ToString(), dv.Value.ToString());

                try
                {
                    monitorMapRW.EnterReadLock();
                    if (monitorMap.TryGetValue(key, out List<MonitoredItem> mis))
                    {
                        foreach (MonitoredItem mi in mis)
                        {
                            if (!(filterHandler?.Invoke(mi.Parameters?.Filter) ?? true))
                            {
                                continue;
                            }

                            if (mi.QueueEvent.Count >= mi.QueueSize)
                            {
                                mi.QueueOverflowed = true;
                            }
                            else
                            {
                                mi.QueueEvent.Enqueue(ev);
                            }

                            if (mi.ParentSubscription.ChangeNotification == Subscription.ChangeNotificationType.None)
                            {
                                mi.ParentSubscription.ChangeNotification = Subscription.ChangeNotificationType.AtPublish;
                            }
                        }
                    }
                }
                finally
                {
                    monitorMapRW.ExitReadLock();
                }
            }

            /// <summary>
            /// Override this method in derived class, to return an object assosiated to new sessions.
            /// </summary>
            /// <param name="sessionInfo">Creation information that can be used to organize objects.</param>
            /// <remarks>
            /// Organizing and reusing objects will allow you to remember session related settings after reconnecting.
            /// </remarks>
            /// <returns>
            /// Returns an object that will be assigned to the session. This object will provided to each session related methods.
            /// </returns>
            public virtual object SessionCreate(SessionCreationInfo sessionInfo)
            {
                return null;
            }

            /// <summary>
            /// Override this method in derived class, to validate the client application information during session creation process.
            /// </summary>
            /// <remarks>
            /// This method can be implemented to check client application against a accept-list or a reject-list, and to validate the client certificate.
            /// </remarks>
            /// <param name="session">Object returned by the <see cref="SessionCreate"/> method.</param>
            /// <param name="clientApplicationDescription">Description of the client application trying to create a session.</param>
            /// <param name="clientCertificate">Certificate provided by the client application.</param>
            /// <param name="sessionName">Session name choosen by the client application.</param>
            /// <returns>Return true to accept the client application or false to reject it.</returns>
            public virtual bool SessionValidateClientApplication(object session, ApplicationDescription clientApplicationDescription, byte[] clientCertificate, string sessionName)
            {
                return true;
            }

            /// <summary>
            /// Override this method in derived class, to validate the user identity token.
            /// </summary>
            /// <param name="session">Object returned by the <see cref="SessionCreate"/> method.</param>
            /// <param name="userIdentityToken">User identity token. Can be a instance of <see cref="UserIdentityAnonymousToken"/> or <see cref="UserIdentityUsernameToken"/>.</param>
            /// <returns>True, when the user token will be accepted. Otherwise false to reject it.</returns>
            public virtual bool SessionValidateClientUser(object session, UserIdentityToken userIdentityToken)
            {
                return true;
            }

            /// <summary>
            /// Override this method in derived class, to validate the secure channel settings the client application requests.
            /// </summary>
            /// <param name="session">Object returned by the <see cref="SessionCreate"/> method.</param>
            /// <param name="securityPolicy">Requested security policy.</param>
            /// <param name="messageSecurityMode">Requested message security mode.</param>
            /// <param name="remoteCertificate">Certificate used by the client application.</param>
            /// <returns>True to activate the session. Otherwise false to reject it.</returns>
            public virtual bool SessionActivateClient(object session, SecurityPolicy securityPolicy, MessageSecurityMode messageSecurityMode, X509Certificate2 remoteCertificate)
            {
                return true;
            }

            /// <summary>
            /// Override this method in derived class, to cleanup the session object on releasing the session.
            /// </summary>
            /// <param name="session">Object returned by the <see cref="SessionCreate"/> method.</param>
            public virtual void SessionRelease(object session)
            {
            }

            /// <summary>
            /// Override this method in derived class, to evaluate session read rights.
            /// </summary>
            /// <param name="session">Object returned by the <see cref="SessionCreate"/> method.</param>
            /// <param name="nodeId">Node id of the node the client try to read.</param>
            /// <returns>True to accept the read request. Otherwise false to reject it.</returns>
            protected virtual bool SessionHasPermissionToRead(object session, NodeId nodeId)
            {
                return true;
            }

            /// <summary>
            /// Override this method in derived class, to provide the value of a node. This method can also be used to provide custom values for the nodes added to the internal address space.
            /// </summary>
            /// <param name="id">Node id of the node.</param>
            /// <returns>The value of the node.</returns>
            protected virtual DataValue HandleReadRequestInternal(NodeId id)
            {
                if (internalAddressSpaceValues.TryGetValue(id, out object value))
                {
                    return new DataValue(value, StatusCode.Good);
                }

                return new DataValue(null, StatusCode.Good);
            }

            /// <summary>
            /// Translates one or more browse paths to NodeIds. Each browse path is constructed of a starting Node and a RelativePath. The specified starting Node identifies the Node from which the RelativePath is based. The RelativePath contains a sequence of ReferenceTypes and BrowseNames.
            /// </summary>
            /// <param name="session">Object returned by the <see cref="SessionCreate"/> method.</param>
            /// <param name="path">Browse path to translate.</param>
            /// <param name="res">List where the results of the translation are added.</param>
            /// <returns>Returns <see cref="StatusCode.Good"/> when path could be translated successful, otherwise a bad status code is returned.</returns>
            public virtual StatusCode HandleTranslateBrowsePathRequest(object session, BrowsePath path, List<BrowsePathTarget> res)
            {
                if (!AddressSpaceTable.TryGetValue(path.StartingNode, out Node node) ||
                    !SessionHasPermissionToRead(session, path.StartingNode))
                {
                    return StatusCode.BadNodeIdUnknown;
                }
                if (path.RelativePath.Length == 0)
                {
                    return StatusCode.BadNothingToDo;
                }

                for (int i = 0; i < path.RelativePath.Length; i++)
                {
                    var rp = path.RelativePath[i];
                    ReferenceNode nref = null;
                    for (int j = 0; j < node.References.Count; j++)
                    {
                        var tref = node.References[j];
                        if (rp.IsInverse != tref.IsInverse)
                        {
                            continue;
                        }

                        if (!rp.IncludeSubtypes && !tref.ReferenceType.Equals(rp.ReferenceTypeId))
                        {
                            continue;
                        }

                        if (rp.IncludeSubtypes && !IsSubtypeOrEqual(tref.ReferenceType, rp.ReferenceTypeId))
                        {
                            continue;
                        }

                        if (!AddressSpaceTable.TryGetValue(tref.Target, out Node target) ||
                            !SessionHasPermissionToRead(session, tref.Target))
                        {
                            continue;
                        }

                        if (target.BrowseName.Equals(rp.TargetName))
                        {
                            nref = node.References[j];
                            node = target;
                            break;
                        }
                    }

                    if (nref == null || node == null)
                    {
                        res.Add(new BrowsePathTarget() { Target = node.Id, RemainingPathIndex = (uint)i });
                        return StatusCode.BadNoMatch;
                    }

                    // Spec. says remainingIndex is index of first unprocessed relative path or max when all processed.
                    var remainingIndex = i + 1 == path.RelativePath.Length ? uint.MaxValue : (uint)i + 1;
                    // Seen other implementation creating multiple instances, but we need it to work for atleast one.
                    res.Add(new BrowsePathTarget() { Target = node.Id, RemainingPathIndex = remainingIndex });
                }

                return StatusCode.Good;
            }

            /// <summary>
            /// Discovers the references of a specified Node.
            /// </summary>
            /// <param name="session">Object returned by the <see cref="SessionCreate"/> method.</param>
            /// <param name="browseDesc">Description of the browse request.</param>
            /// <param name="results">List where the results of the browse request are added.</param>
            /// <param name="maxResults">Indicates the maximum number of references to return.</param>
            /// <param name="cont">Continuation point.</param>
            /// <returns>Returns <see cref="StatusCode.Good"/> when the browse request was successful or <see cref="StatusCode.GoodMoreData"/> when browse request was successful but more data will be available. A bad status is returned, when the browse request fails.</returns>
            public virtual StatusCode HandleBrowseRequest(object session, BrowseDescription browseDesc, List<ReferenceDescription> results, int maxResults, ContinuationPointBrowse cont)
            {
                if (!AddressSpaceTable.TryGetValue(browseDesc.Id, out Node node) ||
                    !SessionHasPermissionToRead(session, browseDesc.Id))
                {
                    return StatusCode.BadNodeIdUnknown;
                }

                bool referenceTypeSpecified = !browseDesc.ReferenceType.EqualsNumeric(0, 0);

                results.Clear();
                for (int i = cont.IsValid ? cont.Offset : 0; i < node.References.Count; i++)
                {
                    var r = node.References[i];

                    if (browseDesc.Direction == BrowseDirection.Forward && r.IsInverse ||
                        browseDesc.Direction == BrowseDirection.Inverse && !r.IsInverse)
                    {
                        continue;
                    }

                    if (referenceTypeSpecified && !browseDesc.IncludeSubtypes && !r.ReferenceType.Equals(browseDesc.ReferenceType))
                    {
                        continue;
                    }

                    if (referenceTypeSpecified && browseDesc.IncludeSubtypes && !IsSubtypeOrEqual(r.ReferenceType, browseDesc.ReferenceType))
                    {
                        continue;
                    }

                    if (results.Count == maxResults)
                    {
                        cont.Offset = i;
                        cont.IsValid = true;

                        // TODO: Set continuation point
                        return StatusCode.GoodMoreData;
                    }

                    NodeId typeDef = NodeId.Zero;
                    if (!AddressSpaceTable.TryGetValue(r.Target, out Node targetNode) ||
                        !SessionHasPermissionToRead(session, r.Target))
                    {
                        results.Add(new ReferenceDescription(r.ReferenceType, !r.IsInverse, r.Target,
                            new QualifiedName(), new LocalizedText(string.Empty), NodeClass.Unspecified, typeDef));
                    }
                    else
                    {
                        if (browseDesc.NodeClassMask > 0 && ((uint)targetNode.GetNodeClass() & browseDesc.NodeClassMask) == 0)
                        {
                            continue;
                        }

                        if (targetNode.References != null && (targetNode is NodeObject || targetNode is NodeVariable))
                        {
                            for (int j = 0; j < targetNode.References.Count; j++)
                            {
                                if (targetNode.References[j].ReferenceType.EqualsNumeric(0, (uint)UAConst.HasTypeDefinition))
                                {
                                    typeDef = targetNode.References[j].Target;
                                }
                            }
                        }
                    }

                    results.Add(new ReferenceDescription(r.ReferenceType, !r.IsInverse, r.Target, targetNode.BrowseName, targetNode.DisplayName, targetNode.GetNodeClass(), typeDef));
                }

                //Console.WriteLine("Browse {0} {1} -> {2}",
                //	browseDesc.Id.ToString(), node.DisplayName.ToString(),
                //	results.Count == 0 ? "(no results)" :
                //	string.Join(", ", results.Select(r => r.DisplayName.ToString())));

                cont.IsValid = false;
                return StatusCode.Good;
            }

            /// <summary>
            /// Override this method in derived class, to process write requests.
            /// </summary>
            /// <param name="session">Object returned by the <see cref="SessionCreate"/> method.</param>
            /// <param name="writeValues">List of attributes to write.</param>
            /// <remarks>
            /// Base implementation rejects all write requests by returning <see cref="StatusCode.BadNotWritable"/>.
            /// </remarks>
            /// <returns>Array of status codes, containing a status code for each writeValue element.</returns>
            public virtual uint[] HandleWriteRequest(object session, WriteValue[] writeValues)
            {
                var respStatus = new uint[writeValues.Length];

                for (int i = 0; i < writeValues.Length; i++)
                {
                    respStatus[i] = (uint)StatusCode.BadNotWritable;
                }

                return respStatus;
            }

            /// <summary>
            /// Override this method in derived class, to process history value read requests.
            /// </summary>
            /// <param name="session">Object returned by the <see cref="SessionCreate"/> method.</param>
            /// <param name="readDetails">Read details object.</param>
            /// <param name="id"></param>
            /// <param name="continuationPoint"></param>
            /// <param name="results">List where the values will be added.</param>
            /// <param name="offsetContinueFit"></param>
            /// <remarks>
            /// Base implementation returns <see cref="StatusCode.BadNotImplemented"/>.
            /// </remarks>
            public virtual uint HandleHistoryReadRequest(object session, object readDetails, HistoryReadValueId id, ContinuationPointHistory continuationPoint, List<DataValue> results, ref int? offsetContinueFit)
            {
                return (uint)StatusCode.BadNotImplemented;
            }

            /// <summary>
            /// Override this method in derived class, to process history update requests.
            /// </summary>
            /// <param name="session">Object returned by the <see cref="SessionCreate"/> method.</param>
            /// <param name="updates"></param>
            /// <remarks>
            /// Base implementation returns <see cref="StatusCode.BadNotImplemented"/> for each update.
            /// </remarks>
            public virtual uint[] HandleHistoryUpdateRequest(object session, HistoryUpdateData[] updates)
            {
                uint[] resps = new uint[updates.Length];
                for (int i = 0; i < updates.Length; i++)
                {
                    resps[i] = (uint)StatusCode.BadNotImplemented;
                }

                return resps;
            }

            /// <summary>
            /// Override this method in derived class, to process history event read requests.
            /// </summary>
            /// <param name="session">Object returned by the <see cref="SessionCreate"/> method.</param>
            /// <param name="readDetails">Read details object.</param>
            /// <param name="id"></param>
            /// <param name="continuationPoint"></param>
            /// <param name="results">List where the events will be added.</param>
            /// <remarks>
            /// Base implementation returns <see cref="StatusCode.BadNotImplemented"/>.
            /// </remarks>
            public virtual uint HandleHistoryEventReadRequest(object session, ReadEventDetails readDetails, HistoryReadValueId id, ContinuationPointHistory continuationPoint, List<object[]> results)
            {
                return (uint)StatusCode.BadNotImplemented;
            }

            /// <summary>
            /// Override this method in derived class, to process register nodes requests send by Clients to register the Nodes that they know they will access repeatedly (e.g. Write, Call). It allows Servers to set up anything needed so that the access operations will be more efficient.
            /// </summary>
            /// <param name="session">Object returned by the <see cref="SessionCreate"/> method.</param>
            /// <param name="nodesToRegister">List of nodes to register.</param>
            public virtual (StatusCode, NodeId[]) HandleRegisterNodesRequest(object session, NodeId[] nodesToRegister)
            {
                return (StatusCode.Good, nodesToRegister);
            }

            /// <summary>
            /// Override this method in derived class, to process a unregister nodes request.
            /// </summary>
            /// <param name="session">Object returned by the <see cref="SessionCreate"/> method.</param>
            /// <param name="nodesToUnregister">List of nodes to unregister.</param>
            /// <returns>Returns <see cref="StatusCode.Good"/> when request handed successful. Otherwise a bad status code is returned.</returns>
            public virtual StatusCode HandleUnregisterNodesRequest(object session, NodeId[] nodesToUnregister)
            {
                return StatusCode.Good;
            }

            /// <summary>
            /// Handles read requests.
            /// </summary>
            /// <param name="session">Object returned by the <see cref="SessionCreate"/> method.</param>
            /// <param name="readValueIds">List of nodeid-attributes pairs to read.</param>
            public virtual DataValue[] HandleReadRequest(object session, ReadValueId[] readValueIds)
            {
                var res = new DataValue[readValueIds.Length];

                for (int i = 0; i < readValueIds.Length; i++)
                {
                    if (!AddressSpaceTable.TryGetValue(readValueIds[i].NodeId, out Node node) ||
                        !SessionHasPermissionToRead(session, readValueIds[i].NodeId))
                    {
                        //Console.WriteLine($"Read node {readValueIds[i].NodeId} unknown {readValueIds[i].AttributeId}");
                        res[i] = new DataValue(null, StatusCode.BadNodeIdUnknown);
                        continue;
                    }

                    if (readValueIds[i].AttributeId == NodeAttribute.Value)
                    {
                        res[i] = HandleReadRequestInternal(readValueIds[i].NodeId);
                    }
                    else if (readValueIds[i].AttributeId == NodeAttribute.NodeId)
                    {
                        res[i] = new DataValue(node.Id, StatusCode.Good);
                    }
                    else if (readValueIds[i].AttributeId == NodeAttribute.NodeClass)
                    {
                        NodeClass nodeClass = node.GetNodeClass();
                        res[i] = new DataValue((int)nodeClass, StatusCode.Good);
                    }
                    else if (readValueIds[i].AttributeId == NodeAttribute.BrowseName)
                    {
                        res[i] = new DataValue(node.BrowseName, StatusCode.Good);
                    }
                    else if (readValueIds[i].AttributeId == NodeAttribute.DisplayName)
                    {
                        res[i] = new DataValue(node.DisplayName, StatusCode.Good);
                    }
                    else if (readValueIds[i].AttributeId == NodeAttribute.Description)
                    {
                        res[i] = new DataValue(node.Description, StatusCode.Good);
                    }
                    else if (readValueIds[i].AttributeId == NodeAttribute.WriteMask)
                    {
                        res[i] = new DataValue(node.WriteMask, StatusCode.Good);
                    }
                    else if (readValueIds[i].AttributeId == NodeAttribute.UserWriteMask)
                    {
                        res[i] = new DataValue(node.UserWriteMask, StatusCode.Good);
                    }
                    else if (readValueIds[i].AttributeId == NodeAttribute.AccessRestrictions)
                    {
                        res[i] = new DataValue((ushort)0, StatusCode.Good);
                    }
                    else if (readValueIds[i].AttributeId == NodeAttribute.IsAbstract && node is NodeReferenceType)
                    {
                        res[i] = new DataValue((node as NodeReferenceType).IsAbstract, StatusCode.Good);
                    }
                    else if (readValueIds[i].AttributeId == NodeAttribute.Symmetric && node is NodeReferenceType)
                    {
                        res[i] = new DataValue((node as NodeReferenceType).IsSymmetric, StatusCode.Good);
                    }
                    else if (readValueIds[i].AttributeId == NodeAttribute.InverseName && node is NodeReferenceType)
                    {
                        res[i] = new DataValue((node as NodeReferenceType).InverseName, StatusCode.Good);
                    }
                    else if (readValueIds[i].AttributeId == NodeAttribute.ContainsNoLoops && node is NodeView)
                    {
                        res[i] = new DataValue((node as NodeView).ContainsNoLoops, StatusCode.Good);
                    }
                    else if (readValueIds[i].AttributeId == NodeAttribute.EventNotifier && node is NodeView)
                    {
                        res[i] = new DataValue((node as NodeView).EventNotifier, StatusCode.Good);
                    }
                    else if (readValueIds[i].AttributeId == NodeAttribute.EventNotifier && node is NodeObject)
                    {
                        res[i] = new DataValue((node as NodeObject).EventNotifier, StatusCode.Good);
                    }
                    else if (readValueIds[i].AttributeId == NodeAttribute.DataType && node is NodeVariable)
                    {
                        res[i] = new DataValue((node as NodeVariable).DataType ?? new NodeId(UAConst.BaseDataType), StatusCode.Good);
                    }
                    else if (readValueIds[i].AttributeId == NodeAttribute.DataType && node is NodeVariableType)
                    {
                        res[i] = new DataValue((node as NodeVariableType).DataType ?? new NodeId(UAConst.BaseDataType), StatusCode.Good);
                    }
                    else if (readValueIds[i].AttributeId == NodeAttribute.AccessLevel && node is NodeVariable)
                    {
                        res[i] = new DataValue((byte)(node as NodeVariable).AccessLevel, StatusCode.Good);
                    }
                    else if (readValueIds[i].AttributeId == NodeAttribute.AccessLevelEx && node is NodeVariable)
                    {
                        res[i] = new DataValue((uint)(node as NodeVariable).AccessLevel, StatusCode.Good);
                    }
                    else if (readValueIds[i].AttributeId == NodeAttribute.UserAccessLevel && node is NodeVariable)
                    {
                        res[i] = new DataValue((byte)(node as NodeVariable).UserAccessLevel, StatusCode.Good);
                    }
                    else if (readValueIds[i].AttributeId == NodeAttribute.Historizing && node is NodeVariable)
                    {
                        res[i] = new DataValue((node as NodeVariable).IsHistorizing, StatusCode.Good);
                    }
                    else if (readValueIds[i].AttributeId == NodeAttribute.MinimumSamplingInterval && node is NodeVariable)
                    {
                        res[i] = new DataValue((node as NodeVariable).MinimumResamplingInterval, StatusCode.Good);
                    }
                    else if (readValueIds[i].AttributeId == NodeAttribute.Executable && node is NodeMethod)
                    {
                        res[i] = new DataValue((node as NodeMethod).IsExecutable, StatusCode.Good);
                    }
                    else if (readValueIds[i].AttributeId == NodeAttribute.UserExecutable && node is NodeMethod)
                    {
                        res[i] = new DataValue((node as NodeMethod).IsUserExecutable, StatusCode.Good);
                    }
                    else if (readValueIds[i].AttributeId == NodeAttribute.ValueRank && node is NodeVariable)
                    {
                        res[i] = new DataValue((int)(node as NodeVariable).ValueRank, StatusCode.Good);
                    }
                    else
                    {
                        res[i] = new DataValue(null, StatusCode.BadAttributeIdInvalid);
                    }

                    //Console.WriteLine($"Read node {readValueIds[i].NodeId} {node.DisplayName.Text} {readValueIds[i].AttributeId} => {res[i].Value ?? "### NULL"}");
                }

                return res;
            }

            /// <summary>
            /// Override this method in derived class, to process method call requests.
            /// </summary>
            public virtual CallMethodResult HandleCallRequest(object session, CallMethodRequest request)
            {
                var inputLength = request.InputArguments.Length;
                var inputResults = Enumerable.Repeat((uint)StatusCode.BadNotImplemented, inputLength).ToArray();
                return new CallMethodResult((uint)StatusCode.BadNotImplemented, inputResults, new object[0]);
            }

            /// <summary>
            /// Checks if target type is a subtype of the parent type.
            /// </summary>
            /// <param name="target">Node id of the target type.</param>
            /// <param name="parent">Node id of the parent type.</param>
            /// <returns>Return true, when taget type id a subtype of parent type. Otherwise false is returned.</returns>
            public bool IsSubtypeOrEqual(NodeId target, NodeId parent)
            {
                if (target.Equals(parent)) { return true; }
                if (parent.EqualsNumeric(0, 0)) { return true; }

                if (!AddressSpaceTable.TryGetValue(parent, out Node node))
                {
                    return false;
                }

                for (int i = 0; i < node.References.Count; i++)
                {
                    var r = node.References[i];
                    if (r.IsInverse) { continue; }

                    if (!r.ReferenceType.EqualsNumeric(0, (uint)UAConst.HasSubtype))
                    {
                        continue;
                    }

                    if (IsSubtypeOrEqual(target, r.Target))
                    {
                        return true;
                    }
                }

                return false;
            }

            private void SetupInternalAddressSpace()
            {
                internalAddressSpaceNodes = new HashSet<NodeId>();
                foreach (var key in AddressSpaceTable.Keys) { internalAddressSpaceNodes.Add(key); }

                internalAddressSpaceValues = new Dictionary<NodeId, object>()
                {
                    { new NodeId(UAConst.Server_ServerArray), new string[0] },
                    { new NodeId(UAConst.Server_NamespaceArray), new string[]
                        {
                            "http://opcfoundation.org/UA/",
                            "http://quantensystems.com/uaSDK2",
                            "http://quantensystems.com/DemoServer"
                        }
                    },
                    { new NodeId(UAConst.Server_ServerStatus_State), (int)ServerState.Running },

                    { new NodeId(UAConst.OperationLimitsType_MaxNodesPerRead), 100 },
                    { new NodeId(UAConst.OperationLimitsType_MaxNodesPerWrite), 100 },
                    { new NodeId(UAConst.OperationLimitsType_MaxNodesPerMethodCall), 100 },
                    { new NodeId(UAConst.OperationLimitsType_MaxNodesPerBrowse), 100 },
                    { new NodeId(UAConst.OperationLimitsType_MaxNodesPerRegisterNodes), 100 },
                    { new NodeId(UAConst.OperationLimitsType_MaxNodesPerTranslateBrowsePathsToNodeIds), 100 },
                    { new NodeId(UAConst.OperationLimitsType_MaxNodesPerNodeManagement), 100 },
                    { new NodeId(UAConst.OperationLimitsType_MaxMonitoredItemsPerCall), 100 },
                    { new NodeId(UAConst.OperationLimitsType_MaxNodesPerHistoryReadData), 100 },
                    { new NodeId(UAConst.OperationLimitsType_MaxNodesPerHistoryUpdateData), 100 },
                    { new NodeId(UAConst.OperationLimitsType_MaxNodesPerHistoryReadEvents), 100 },
                    { new NodeId(UAConst.OperationLimitsType_MaxNodesPerHistoryUpdateEvents), 100 },

                    { new NodeId(UAConst.Server_ServerStatus_StartTime), 0 },
                    { new NodeId(UAConst.Server_ServerStatus_CurrentTime), 0 },
                    { new NodeId(UAConst.Server_ServerStatus_SecondsTillShutdown), 0 },
                    { new NodeId(UAConst.Server_ServerStatus_BuildInfo_ProductUri), "product" },
                    { new NodeId(UAConst.Server_ServerStatus_BuildInfo_ManufacturerName), "manufacturer" },
                    { new NodeId(UAConst.Server_ServerStatus_BuildInfo_ProductName), "product" },
                    { new NodeId(UAConst.Server_ServerStatus_BuildInfo_SoftwareVersion), 1.0 },
                    { new NodeId(UAConst.Server_ServerStatus_BuildInfo_BuildNumber), 1.0 },
                    { new NodeId(UAConst.Server_ServerStatus_BuildInfo_BuildDate), 0 }
                };
            }
        }
    }
}
