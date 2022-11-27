using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.Runtime.CompilerServices;
using System.Xml;
using System.Xml.Serialization;

namespace tsharkService.Structures
{
    public class PCapTreeNodeinfo
    #region
    {
        public string LeadingChar = null;
        public List<string> ProtocolElmt = null;
        public string Protocol = null;
    }
    #endregion
    public class StatParameter
    #region
    {
        public string CmdType { set; get; }
        public string PipeName { set; get; }
        public string PcapFileName { set; get; }
        public long DeviceId { set; get; }
        public List<string> ListCmd { set; get; }
    }
    #endregion
    [Serializable]
    [DataContract()]
    public class PcapStatDef
    #region
    {
        public Enums.StatView StatView = Enums.StatView.None;
        public string GroupName { set; get; }
        public Enums.StatisticsType StatType = Enums.StatisticsType.None;
        [DataMember] public string StatCmd { set; get; }
        [DataMember] public string Title { set; get; }

        public bool IsIoStat => StatCmd.StartsWith("io,stat");
    }
    #endregion
    [Serializable]
    [DataContract()]
    public class ConversationItem
    #region
    {
        [DataMember] public string src_address;    /**< source address */
        [DataMember] public string dst_address;    /**< destination address */
        [DataMember] public Enums.port_type ptype;          /**< port_type (e.g. PT_TCP) */
        [DataMember] public uint src_port;       /**< source port */
        [DataMember] public uint dst_port;       /**< destination port */
        [DataMember] public uint conv_id;        //conv_id_t /**< conversation id */

        [DataMember] public ulong rx_frames;      /**< number of received packets */
        [DataMember] public ulong tx_frames;      /**< number of transmitted packets */
        [DataMember] public ulong rx_bytes;       /**< number of received bytes */
        [DataMember] public ulong tx_bytes;       /**< number of transmitted bytes */

        [DataMember] public nstime_t start_time;     /**< relative start time for the conversation */
        [DataMember] public nstime_t stop_time;      /**< relative stop time for the conversation */
        [DataMember] public nstime_t start_abs_time; /**< absolute start time for the conversation */
        internal ConversationItem(conv_item_t item)
        {
            this.src_port = item.src_port;
            this.dst_port = item.dst_port;
            this.ptype = item.ptype;
            this.conv_id = item.conv_id;
            this.rx_frames = item.rx_frames;
            this.tx_frames = item.tx_frames;
            this.rx_bytes = item.rx_bytes;
            this.tx_bytes = item.tx_bytes;
            this.start_time = item.start_time;
            this.stop_time = item.stop_time;
            this.start_abs_time = item.start_abs_time;

            unsafe
            {
                IntPtr pntAddress = Marshal.AllocHGlobal(sizeof(address));
                Marshal.StructureToPtr(item.src_address, pntAddress, false);
                var intPtrStr = tsharkWrapper.wz_address_to_str(pntAddress, 0);
                this.src_address = Marshal.PtrToStringAnsi(intPtrStr);

                Marshal.StructureToPtr(item.dst_address, pntAddress, false);
                intPtrStr = tsharkWrapper.wz_address_to_str(pntAddress, 0);
                this.dst_address = Marshal.PtrToStringAnsi(intPtrStr);
                Marshal.FreeHGlobal(pntAddress);
            }
        }
        public ConversationItem() { }
    };
    #endregion
    [Serializable]
    [DataContract()]
    public class EndpointItem
    #region
    {
        [DataMember] public string address;    /**< source address */
        [DataMember] public uint port;       /**< source port */
        [DataMember] public Enums.port_type ptype;          /**< port_type (e.g. PT_TCP) */

        [DataMember] public ulong rx_frames;      /**< number of received packets */
        [DataMember] public ulong tx_frames;      /**< number of transmitted packets */
        [DataMember] public ulong rx_bytes;       /**< number of received bytes */
        [DataMember] public ulong tx_bytes;       /**< number of transmitted bytes */
        internal EndpointItem(hostlist_talker_t item)
        {
            this.port = item.port;
            this.ptype = item.ptype;
            this.rx_frames = item.rx_frames;
            this.tx_frames = item.tx_frames;
            this.rx_bytes = item.rx_bytes;
            this.tx_bytes = item.tx_bytes;
            unsafe
            {
                IntPtr pntAddress = Marshal.AllocHGlobal(sizeof(address));
                Marshal.StructureToPtr(item.myaddress, pntAddress, false);
                var intPtrStr = tsharkWrapper.wz_address_to_str(pntAddress, 0);
                this.address = Marshal.PtrToStringAnsi(intPtrStr);
                Marshal.FreeHGlobal(pntAddress);
            }
        }
        public EndpointItem() { }
    };
    #endregion
    #region RTD
    [Serializable]
    [DataContract()]
    public class RtdStatTable
    #region
    {
        [DataMember] public string filter;//char*
        [DataMember] public List<RtdTimestat> time_stats; //rtd_timestat* 
        internal RtdStatTable()
        {
            this.time_stats = new List<RtdTimestat>();
        }
    };
    #endregion
    [Serializable]
    [DataContract()]
    public class RtdTimestat
    #region
    {
        [DataMember] public List<timestat_t> rtd; //timestat_t*
        [DataMember] public uint open_req_num;
        [DataMember] public uint disc_rsp_num;
        [DataMember] public uint req_dup_num;
        [DataMember] public uint rsp_dup_num;
        internal RtdTimestat(rtd_timestat item)
        {
            this.open_req_num = item.open_req_num;
            this.disc_rsp_num = item.disc_rsp_num;
            this.req_dup_num = item.req_dup_num;
            this.rsp_dup_num = item.rsp_dup_num;
            this.rtd = new List<timestat_t>();

            for (int g = 0; g < item.num_timestat; ++g)
            {
                var item2 = (timestat_t)Marshal.PtrToStructure(Marshal.ReadIntPtr(item.rtd, g * SharkService.PointerSize), typeof(timestat_t));
                this.rtd.Add(item2);
            }
        }
        public RtdTimestat() { }
    };
    #endregion
    #endregion
    #region Stat tree
    [Serializable]
    [DataContract()]
    public class Stat_Tree
    #region
    {
        [DataMember] public string filter;//char*
                                          /* times */
        [DataMember] public double start;
        [DataMember] public double elapsed;
        [DataMember] public double now;

        [DataMember] public int st_flags;
        [DataMember] public int num_columns;
        [DataMember] public string display_name; //gchar*
        [DataMember] public Stat_Node root; //wz_stat_node*
        public Stat_Tree() { }
        internal Stat_Tree(wz_stats_tree item)
        {
            this.start = item.start;
            this.elapsed = item.elapsed;
            this.now = item.now;
            this.st_flags = item.st_flags;
            this.num_columns = item.num_columns;

            //if (item.filter != IntPtr.Zero)
            //    statTreeClass.filter = Marshal.PtrToStringAnsi(item.filter);
            if (item.display_name != IntPtr.Zero)
                this.display_name = Marshal.PtrToStringAnsi(item.display_name);
            if (item.root != IntPtr.Zero)
            {
                var wNode = LoadStatNode(item.root);
                this.root = new Structures.Stat_Node()
                {
                    name = wNode.name,
                    children = wNode.children,
                };
            }
            Structures.Stat_Node LoadStatNode(IntPtr nodePtr)
            {
                var wNode = (Structures.wz_stat_node)Marshal.PtrToStructure(nodePtr, typeof(Structures.wz_stat_node));
                var statNode = new Structures.Stat_Node(wNode);

                if (wNode.children != IntPtr.Zero)
                {
                    statNode.children = new List<Structures.Stat_Node>();
                    var children = (Structures.GArray)Marshal.PtrToStructure(wNode.children, typeof(Structures.GArray));
                    for (int m = 0; m < children.len; ++m)
                    {
                        IntPtr pItemArray = Marshal.ReadIntPtr(children.data, m * SharkService.PointerSize);
                        if (pItemArray == IntPtr.Zero)
                            continue;

                        statNode.children.Add(LoadStatNode(pItemArray));
                    }
                }
                return statNode;
            }
        }
    };
    #endregion
    [Serializable]
    [DataContract()]
    public class Stat_Node
    #region
    {
        [DataMember] public string name; //char*
        [DataMember] public int counter = 0;

        [DataMember] public long total = long.MaxValue;
        [DataMember] public int minvalue = int.MaxValue;
        [DataMember] public int maxvalue = int.MaxValue;
        [DataMember] public float rate = float.MaxValue;
        [DataMember] public float percent = float.MaxValue;

        [DataMember] public float burst_rate = float.MaxValue;
        [DataMember] public double burst_time = double.MaxValue;

        [DataMember] public List<Stat_Node> children;//GPtrArray*	
        internal Stat_Node() { }
        internal Stat_Node(wz_stat_node wNode)
        {
            this.name = Marshal.PtrToStringAnsi(wNode.name);
            this.counter = wNode.counter;
            this.total = wNode.total;
            this.minvalue = wNode.minvalue;
            this.maxvalue = wNode.maxvalue;
            this.rate = wNode.rate;
            this.percent = wNode.percent;
            this.burst_rate = wNode.burst_rate;
            this.burst_time = wNode.burst_time;
        }
    };
    #endregion
    #endregion
    [Serializable]
    [DataContract()]
    public class ProtocolHierarchyNode
    #region
    {
        [DataMember] public string ProtocolName;
        [DataMember] public uint Packets = 0;
        [DataMember] public ulong Bytes = 0;

        [DataMember] public ProtocolHierarchyNode Parent { set; get; }
        [DataMember] public List<ProtocolHierarchyNode> Children { set; get; }
        public ProtocolHierarchyNode() { }
        internal ProtocolHierarchyNode(wz_phs_t wzNode)
        {
            this.ProtocolName = Marshal.PtrToStringAnsi(wzNode.proto_name);
            this.Packets = wzNode.frames;
            this.Bytes = wzNode.bytes;
        }
    }
    #endregion
    [Serializable]
    [DataContract()]
    public class Stat_SimpleTable
    #region
    {
        [DataMember] public string Name { set; get; }
        [DataMember] public string Filter { set; get; }
        [DataMember] public List<string> Columns { set; get; }
        [DataMember] public List<Stat_SimpleTableSub> SubTables { set; get; }
        public Stat_SimpleTable() { }
        internal Stat_SimpleTable(wz_simple_table table)
        {
            this.Name = Marshal.PtrToStringAnsi(table.name);
            this.Filter = Marshal.PtrToStringAnsi(table.filter);
            this.Columns = new List<string>();
            this.SubTables = new List<Structures.Stat_SimpleTableSub>();

            var columnArray = (Structures.GArray)Marshal.PtrToStructure(table.columns, typeof(Structures.GArray));
            for (int k = 0; k < columnArray.len; ++k)
                this.Columns.Add(Marshal.PtrToStringAnsi(Marshal.ReadIntPtr(columnArray.data, k * SharkService.PointerSize)));

            var subTableArray = (Structures.GArray)Marshal.PtrToStructure(table.subTables, typeof(Structures.GArray));
            for (int k = 0; k < subTableArray.len; ++k)
            {
                var wzSubTable = new Structures.Stat_SimpleTableSub();
                this.SubTables.Add(wzSubTable);

                var subTable = (Structures._wz_simple_subtable)Marshal.PtrToStructure(Marshal.ReadIntPtr(subTableArray.data, k * SharkService.PointerSize), typeof(Structures._wz_simple_subtable));
                wzSubTable.Name = Marshal.PtrToStringAnsi(subTable.name);
                wzSubTable.Rows = new List<List<(string, double)>>();

                var rowArray = (Structures.GArray)Marshal.PtrToStructure(subTable.Rows, typeof(Structures.GArray));
                for (int row = 0; row < rowArray.len; ++row)
                {
                    var fields = new List<(string, double)>();
                    wzSubTable.Rows.Add(fields);

                    var colArray = (Structures.GArray)Marshal.PtrToStructure(Marshal.ReadIntPtr(rowArray.data, row * SharkService.PointerSize), typeof(Structures.GArray));
                    for (int col = 0; col < colArray.len; ++col)
                    {
                        var wzField = (Structures._wz_simple_field)Marshal.PtrToStructure(Marshal.ReadIntPtr(colArray.data, col * SharkService.PointerSize), typeof(Structures._wz_simple_field));
                        if (wzField.string_value != IntPtr.Zero)
                            fields.Add((Marshal.PtrToStringAnsi(wzField.string_value), double.NaN));
                        else
                            fields.Add((null, wzField.n_value));
                    }
                }
            }
        }
    }
    #endregion
    [Serializable]
    [DataContract()]
    public class Stat_SimpleTableSub
    #region
    {
        [DataMember] public string Name { set; get; }
        [DataMember] public List<List<(string Text, double NumValue)>> Rows { set; get; }
    }
    #endregion
    #region SRT
    [Serializable]
    [DataContract()]
    public class Stat_SrtTable
    #region
    {
        [DataMember] public string Type { set; get; }
        [DataMember] public string Filter { set; get; }
        [DataMember] public List<Structures.wz_srt_row> Rows { set; get; }
        public Stat_SrtTable() { }
        internal Stat_SrtTable(wz_srt_table table)
        {
            this.Type = Marshal.PtrToStringAnsi(table.type);
            this.Filter = Marshal.PtrToStringAnsi(table.filter);
            this.Rows = new List<Structures.wz_srt_row>();

            var rowArray = (Structures.GArray)Marshal.PtrToStructure(table.Rows, typeof(Structures.GArray));
            for (int row = 0; row < rowArray.len; ++row)
                this.Rows.Add((Structures.wz_srt_row)Marshal.PtrToStructure(Marshal.ReadIntPtr(rowArray.data, row * SharkService.PointerSize), typeof(Structures.wz_srt_row)));
        }
    }
    #endregion
    #endregion
    #region simple tree
    [Serializable]
    [DataContract()]
    public class simple_treenode_Root
    {
        [DataMember] public List<byte> bytes;
        [DataMember] public List<simple_treenode> children;
    }
    [Serializable]
    [DataContract()]
    public class simple_treenode
    {
        [DataMember] public string name;
        [DataMember] public string abbrev;
        [DataMember] public List<simple_treenode> children;
    }
    #endregion
    #region Sip
    [Serializable]
    [DataContract()]
    public class Stat_SIP
    {
        [DataMember] public string filter;//char* 
        [DataMember] public uint packets;     /* number of sip packets, including continuations */
        [DataMember] public uint resent_packets;
        [DataMember] public uint average_setup_time;
        [DataMember] public uint max_setup_time;
        [DataMember] public uint min_setup_time;
        [DataMember] public uint no_of_completed_calls;
        [DataMember] public uint total_setup_time;
        [DataMember] public List<wz_sip_stat_item> RequestArray;//wz_sip_stats_item GPtrArray*
        [DataMember] public List<wz_sip_stat_item> ResponseArray;//wz_sip_stats_item array
        public Stat_SIP() { }
        internal Stat_SIP(wz_sip_stat wItemRoot)
        {
            this.filter = Marshal.PtrToStringAnsi(wItemRoot.filter);
            this.average_setup_time = wItemRoot.average_setup_time;
            this.max_setup_time = wItemRoot.max_setup_time;
            this.min_setup_time = wItemRoot.min_setup_time;
            this.packets = wItemRoot.packets;
            this.resent_packets = wItemRoot.resent_packets;
            this.RequestArray = new List<Structures.wz_sip_stat_item>();

            var dataArray = (Structures.GArray)Marshal.PtrToStructure(wItemRoot.RequestArray, typeof(Structures.GArray));
            for (int m = 0; m < dataArray.len; ++m)
            {
                IntPtr pItemArray = Marshal.ReadIntPtr(dataArray.data, m * SharkService.PointerSize);
                if (pItemArray == IntPtr.Zero)
                    continue;

                var wItem = (Structures.wz_sip_stat_item)Marshal.PtrToStructure(pItemArray, typeof(Structures.wz_sip_stat_item));
                this.RequestArray.Add(wItem);
            }
            dataArray = (Structures.GArray)Marshal.PtrToStructure(wItemRoot.ResponseArray, typeof(Structures.GArray));
            for (int m = 0; m < dataArray.len; ++m)
            {
                IntPtr pItemArray = Marshal.ReadIntPtr(dataArray.data, m * SharkService.PointerSize);
                if (pItemArray == IntPtr.Zero)
                    continue;

                var wItem = (Structures.wz_sip_stat_item)Marshal.PtrToStructure(pItemArray, typeof(Structures.wz_sip_stat_item));
                this.ResponseArray.Add(wItem);
            }
        }
    };
    #endregion
    #region Sctp
    [Serializable]
    [DataContract()]
    public class Stat_Sctp
    {
        [DataMember] public uint totalPackeks;
        [DataMember] public List<Sctp_item> Items;
    };
    [Serializable]
    [DataContract()]
    public class Sctp_item
    {
        [DataMember] public string srcAddr;
        [DataMember] public string destAddr;
        [DataMember] public ushort sport;
        [DataMember] public ushort dport;
        [DataMember] public uint Data;
        [DataMember] public uint Sack;
        [DataMember] public uint HBeat;
        [DataMember] public uint HBeatAck;
        [DataMember] public uint Init;
        [DataMember] public uint InitAck;
        [DataMember] public uint Cookie;
        [DataMember] public uint CookieAck;
        [DataMember] public uint Abort;
        [DataMember] public uint Error;
        internal Sctp_item(wz_sctp_item wItem)
        {
            this.srcAddr = Marshal.PtrToStringAnsi(wItem.srcAddr);
            this.destAddr = Marshal.PtrToStringAnsi(wItem.destAddr);
            this.sport = wItem.sport;
            this.dport = wItem.dport;

            this.Data = wItem.Data;
            this.Sack = wItem.Sack;
            this.HBeat = wItem.HBeat;
            this.HBeatAck = wItem.HBeatAck;
            this.Init = wItem.Init;
            this.InitAck = wItem.InitAck;
            this.Cookie = wItem.Cookie;
            this.CookieAck = wItem.CookieAck;
            this.Abort = wItem.Abort;
            this.Error = wItem.Error;
        }
        public Sctp_item() { }
    };
    #endregion
    #region wsp
    [Serializable]
    [DataContract()]
    public class Stat_Wsp
    {
        [DataMember] public List<wz_wsp_item> WSP;//GPtrArray*
        [DataMember] public List<wz_wsp_reply_item> ReplyPackets;//GPtrArray*
        public Stat_Wsp()
        {
            this.WSP = new List<Structures.wz_wsp_item>();
            this.ReplyPackets = new List<Structures.wz_wsp_reply_item>();
        }
    };
    #endregion
    #region LTE RLC
    [Serializable]
    [DataContract()]
    public class Stat_Rlc_LTE
    {
        [DataMember] public ushort number_of_ues;
        [DataMember] public uint total_frames;

        [DataMember] public uint bcch_frames;
        [DataMember] public uint bcch_bytes;
        [DataMember] public uint pcch_frames;
        [DataMember] public uint pcch_bytes;

        [DataMember] public List<wz_rlc_lte_row_data> Rows;
        internal Stat_Rlc_LTE(wz_rlc_lte wItem)
        {
            this.number_of_ues = wItem.number_of_ues;
            this.total_frames = wItem.total_frames;
            this.bcch_frames = wItem.bcch_frames;
            this.bcch_bytes = wItem.bcch_bytes;
            this.pcch_frames = wItem.pcch_frames;
            this.pcch_bytes = wItem.pcch_bytes;
            this.Rows = new List<wz_rlc_lte_row_data>();

            var dataArray = (Structures.GArray)Marshal.PtrToStructure(wItem.Rows, typeof(Structures.GArray));
            for (int m = 0; m < dataArray.len; ++m)
            {
                IntPtr pItemArray = Marshal.ReadIntPtr(dataArray.data, m * SharkService.PointerSize);
                if (pItemArray == IntPtr.Zero)
                    continue;

                var rowItem = (Structures.wz_rlc_lte_row_data)Marshal.PtrToStructure(pItemArray, typeof(Structures.wz_rlc_lte_row_data));
                this.Rows.Add(rowItem);
            }
        }
        public Stat_Rlc_LTE() { }
    };
    #endregion
    #region LTE MAC
    [Serializable]
    [DataContract()]
    public class Stat_Mac_LTE
    {
        [DataMember] public ushort max_ul_ues_in_tti;
        [DataMember] public uint max_dl_ues_in_tti;

        [DataMember] public uint mib_frames;
        [DataMember] public uint sib_frames;
        [DataMember] public uint sib_bytes;
        [DataMember] public uint pch_frames;
        [DataMember] public uint pch_bytes;
        [DataMember] public uint pch_paging_ids;
        [DataMember] public uint rar_frames;
        [DataMember] public uint rar_entries;
        [DataMember] public ushort number_of_ues;
        [DataMember] public ushort number_of_rntis;
        [DataMember] public ushort number_of_ueids;

        [DataMember] public List<wz_mac_lte_row_data> Rows;
        internal Stat_Mac_LTE(wz_mac_lte wItem)
        {
            this.max_ul_ues_in_tti = wItem.max_ul_ues_in_tti;
            this.max_dl_ues_in_tti = wItem.max_dl_ues_in_tti;
            this.mib_frames = wItem.mib_frames;
            this.sib_frames = wItem.sib_frames;
            this.sib_bytes = wItem.sib_bytes;
            this.pch_frames = wItem.pch_frames;
            this.pch_bytes = wItem.pch_bytes;
            this.pch_paging_ids = wItem.pch_paging_ids;
            this.rar_frames = wItem.rar_frames;
            this.rar_entries = wItem.rar_entries;
            this.number_of_ues = wItem.number_of_ues;
            this.number_of_rntis = wItem.number_of_rntis;
            this.number_of_ueids = wItem.number_of_ueids;
            this.Rows = new List<wz_mac_lte_row_data>();

            var dataArray = (Structures.GArray)Marshal.PtrToStructure(wItem.Rows, typeof(Structures.GArray));
            for (int m = 0; m < dataArray.len; ++m)
            {
                IntPtr pItemArray = Marshal.ReadIntPtr(dataArray.data, m * SharkService.PointerSize);
                if (pItemArray == IntPtr.Zero)
                    continue;

                var rowItem = (Structures.wz_mac_lte_row_data)Marshal.PtrToStructure(pItemArray, typeof(Structures.wz_mac_lte_row_data));
                this.Rows.Add(rowItem);
            }
        }
        public Stat_Mac_LTE() { }
    };
    #endregion
    #region RTP
    [Serializable]
    [DataContract()]
    public struct Rtp_stream
    {
        [DataMember] public wz_rtp_stream Data;
        [DataMember] public List<wz_rtp_Packet> packets;
    };
    #region VoIP
    [Serializable]
    [DataContract()]
    public class Voip_calls_info
    {
        [DataMember] public string call_state;
        [DataMember] public string call_id;
        [DataMember] public string from_identity;
        [DataMember] public string to_identity;
        [DataMember] public string initial_speaker;
        [DataMember] public uint npackets;
        [DataMember] public string protocol_name;
        [DataMember] public string call_comment;
        [DataMember] public ushort call_num;
        [DataMember] public double start_rel_ts;
        [DataMember] public double stop_rel_ts;
        internal Voip_calls_info(wz_voip_calls_info wItem)
        {
            if (wItem.call_state != IntPtr.Zero) this.call_state = Marshal.PtrToStringAnsi(wItem.call_state);
            if (wItem.call_id != IntPtr.Zero) this.call_id = Marshal.PtrToStringAnsi(wItem.call_id);
            if (wItem.from_identity != IntPtr.Zero) this.from_identity = Marshal.PtrToStringAnsi(wItem.from_identity);
            if (wItem.to_identity != IntPtr.Zero) this.to_identity = Marshal.PtrToStringAnsi(wItem.to_identity);
            if (wItem.initial_speaker != IntPtr.Zero) this.initial_speaker = Marshal.PtrToStringAnsi(wItem.initial_speaker);
            this.npackets = wItem.npackets;
            if (wItem.protocol_name != IntPtr.Zero) this.protocol_name = Marshal.PtrToStringAnsi(wItem.protocol_name);
            if (wItem.call_comment != IntPtr.Zero) this.call_comment = Marshal.PtrToStringAnsi(wItem.call_comment);
            this.call_num = wItem.call_num;
            this.start_rel_ts = wItem.start_rel_ts;
            this.stop_rel_ts = wItem.stop_rel_ts;
        }
        public Voip_calls_info() { }
    };
    [Serializable]
    [DataContract()]
    public class Seq_analysis_item
    {
        [DataMember] public uint frame_number;
        [DataMember] public string src_addr;//gchar*
        [DataMember] public ushort port_src;
        [DataMember] public string dst_addr;
        [DataMember] public ushort port_dst;
        [DataMember] public string frame_label;                 /**< the label on top of the arrow */
        [DataMember] public string time_str;                    /**< timestamp */
        [DataMember] public string comment;                     /**< a comment that appears at the right of the graph */
        [DataMember] public ushort conv_num;                   /**< The conversation number. Used for coloring VoIP calls. */
        [DataMember] public string protocol;                    /**< the label of the protocol defined in the IP packet */
        internal Seq_analysis_item(wz_seq_analysis_item wItem)
        {
            this.frame_number = wItem.frame_number;
            if (wItem.src_addr != IntPtr.Zero) this.src_addr = Marshal.PtrToStringAnsi(wItem.src_addr);
            this.port_src = wItem.port_src;
            if (wItem.dst_addr != IntPtr.Zero) this.dst_addr = Marshal.PtrToStringAnsi(wItem.dst_addr);
            this.port_dst = wItem.port_dst;
            if (wItem.frame_label != IntPtr.Zero) this.frame_label = Marshal.PtrToStringAnsi(wItem.frame_label);
            if (wItem.time_str != IntPtr.Zero) this.time_str = Marshal.PtrToStringAnsi(wItem.time_str);
            if (wItem.comment != IntPtr.Zero) this.comment = Marshal.PtrToStringAnsi(wItem.comment);
            this.conv_num = wItem.conv_num;
            if (wItem.protocol != IntPtr.Zero) this.protocol = Marshal.PtrToStringAnsi(wItem.protocol);
        }
        public Seq_analysis_item() { }
    };
    #endregion
    #endregion
    #region string follow
    [Serializable]
    [DataContract()]
    public class Follow_record
    {
        [DataMember] public int is_server;//gboolean
        [DataMember] public uint packet_num;
        [DataMember] public uint seq; /* TCP only */
        [DataMember] public List<byte> data;//GByteArray*
        internal Follow_record(wz_follow_record_t wItem)
        {
            is_server = wItem.is_server;
            packet_num = wItem.packet_num;
            seq = wItem.seq;
            data = new List<byte>();

            var valArray = (Structures.GArray)Marshal.PtrToStructure(wItem.data, typeof(Structures.GArray));
            if (valArray.len == 0)
                return;

            unsafe
            {
                var sourcePtr = (byte*)valArray.data;
                for (int r = 0; r < valArray.len; ++r)
                    this.data.Add(*sourcePtr++);
            }
        }
        public Follow_record() { }
    };
    #endregion
    #region expert info
    [Serializable]
    [DataContract()]
    public class expert_entry
    {
        [DataMember] public string Severity;
        public int frequency => this.Packets == null ? 0 : this.Packets.Count();
        [DataMember] public string protocol;
        [DataMember] public string summary;

        [DataMember] public string groupStr;
        [DataMember] public List<expert_packet> Packets;

        public expert_entry(wz_expert_entry wItem)
        {
            this.protocol = Marshal.PtrToStringAnsi(wItem.protocol);
            this.summary = Marshal.PtrToStringAnsi(wItem.summary);
            this.groupStr = Marshal.PtrToStringAnsi(wItem.groupStr);

            this.Packets = new List<expert_packet>();
            if (wItem.Packets == IntPtr.Zero)
                return;

            var valArray = (Structures.GArray)Marshal.PtrToStructure(wItem.Packets, typeof(Structures.GArray));
            if (valArray.len == 0)
                return;

            for (int m = 0; m < valArray.len; ++m)
            {
                IntPtr pItemArray = Marshal.ReadIntPtr(valArray.data, m * SharkService.PointerSize);
                if (pItemArray == IntPtr.Zero)
                    continue;

                this.Packets.Add(new expert_packet((wz_expert_packet)Marshal.PtrToStructure(pItemArray, typeof(wz_expert_packet))));
            }
        }
        public expert_entry() { }
    };
    [Serializable]
    [DataContract()]
    public class expert_packet
    {
        [DataMember] public uint num;
        [DataMember] public string KeyInfo;
        public expert_packet(wz_expert_packet wItem)
        {
            this.num = wItem.num;
            this.KeyInfo = Marshal.PtrToStringAnsi(wItem.KeyInfo);
        }
        public expert_packet() { }
    };
    #endregion
    /// <summary>
    /// ///////////////////////////////////////////////////////////////
    /// </summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 8)]
    public struct wz_LoadParameters
    #region
    {
        public IntPtr cf_name; //char* 
        public IntPtr filter;//char*
        public int outputFlag;
        public int ShallCreateProtocolTree;

        public byte FrameIndexInsteadOfTime;
        public int fieldCount;
        public IntPtr requestedFields;//char** 
        public IntPtr requestedFieldLoadFlags;//BYTE* 

        public int cmdCount;
        public IntPtr requestedCmds;//char** 

        public uint frameNumber;
    }
    #endregion
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 8)]
    public struct LoadResult
    #region
    {
        public byte FrameIndexInsteadOfTime;
        public int FieldCount;
        public IntPtr output_field_ftype;   //ftenum_t*
        public IntPtr FieldDataArrays;  //GArray**			
        public IntPtr FieldIndexArrays; //GArray**
        public IntPtr FieldNeedIndexArray;  //guint8*
        public IntPtr FieldNeedSaved;   //guint8*

        public IntPtr FrameInfo;//GArray**
        public IntPtr errorInfo;//GPtrArray*

        public IntPtr FrameSummary;//frame summary

        //stat: conversation
        public IntPtr Stat_ConvTypeArray; //GPtrArray*
        public IntPtr Stat_ConvArray; //GPtrArray* 

        //stat: Endpoints
        public IntPtr Stat_EndpointTypeArray;//GPtrArray* 
        public IntPtr Stat_EndpointArray;//GPtrArray* 

        //stat: response time delay (rtd)
        public IntPtr Stat_RtdTypeArray; //GPtrArray*
        public IntPtr Stat_RtdArray; //GPtrArray* 
                                     //stat: tree
        public IntPtr Stat_TreeArray; //GPtrArray* 
        public IntPtr Simple_Treenode;//wz_simple_node* 
        public IntPtr Stat_ProtocolHierarchy; //protocol hierarchy
        public IntPtr Stat_SimpleTables;//wz_simple_table
        public IntPtr Stat_SrtTables;//wz_srt_table array //GPtrArray*
        public IntPtr Stat_SIP;// wz_sip_stats*
        public IntPtr Stat_Sctp;//*wz_sctp
        public IntPtr Stat_Wsp;//wz_wsp*
        public IntPtr Stat_Rlc_LTE;//wz_rlc_lte*
        public IntPtr Stat_Mac_LTE;//wz_mac_lte*
        public IntPtr Stat_io_stat_t;//wz_io_stat_t
        public IntPtr Stat_rtp_stat;//Stat_rtp_stat
        public IntPtr Stat_VoIP_Calls;//wz_voip_calls_info_t
        public IntPtr List_VoIP_Seqence;//wz_seq_analysis_item
        public IntPtr List_FollowRecords;//wz_follow_record_t
        public IntPtr List_ExpertInfo;//expert_entry
    }
    #endregion
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 8)]
    public struct GArray
    #region
    {
        public IntPtr data;
        public uint len;
    };
    #endregion

    #region Stat: conversation data
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 8)]
    internal struct address
    #region
    {
        public int type;         /* type of address */
        public int len;          /* length of address, in bytes */
        public IntPtr data;         /* const void   *data;  pointer to address data */

        /* private */
        IntPtr priv; //void         *priv;
    };
    #endregion
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 8)]
    internal struct conv_item_t
    #region Conversation information
    {
        public IntPtr dissector_info;//ct_dissector_info_t *dissector_info; /**< conversation information provided by dissector */
        public address src_address;    /**< source address */
        public address dst_address;    /**< destination address */
        public Enums.port_type ptype;          /**< port_type (e.g. PT_TCP) */
        public uint src_port;       /**< source port */
        public uint dst_port;       /**< destination port */
        public uint conv_id;        //conv_id_t /**< conversation id */

        public ulong rx_frames;      /**< number of received packets */
        public ulong tx_frames;      /**< number of transmitted packets */
        public ulong rx_bytes;       /**< number of received bytes */
        public ulong tx_bytes;       /**< number of transmitted bytes */

        public nstime_t start_time;     /**< relative start time for the conversation */
        public nstime_t stop_time;      /**< relative stop time for the conversation */
        public nstime_t start_abs_time; /**< absolute start time for the conversation */

        public int modified;       //gboolean      /**< new to redraw the row (only used in GTK+) */
    };
    #endregion
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 8)]
    internal struct hostlist_talker_t
    {
        public IntPtr dissector_info; /**< conversation information provided by dissector */
        public address myaddress;      /**< address */
        public Enums.port_type ptype;       /**< port_type (e.g. PT_TCP) */
        public uint port;           /**< port */

        public ulong rx_frames;      /**< number of received packets */
        public ulong tx_frames;      /**< number of transmitted packets */
        public ulong rx_bytes;       /**< number of received bytes */
        public ulong tx_bytes;       /**< number of transmitted bytes */

        public int modified;      /**< new to redraw the row */
    };
    [Serializable]
    [DataContract()]
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 8)]
    public struct nstime_t
    #region
    {
        [DataMember] public long secs;//time_t
        [DataMember] public int nsecs;
    };
    #endregion
    #endregion
    #region stat: tree
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 8)]
    internal struct wz_stat_node
    {
        public IntPtr name; //char*
        public int counter;

        public long total;
        public int minvalue;
        public int maxvalue;
        public float rate;
        public float percent;

        public float burst_rate;
        public double burst_time;

        public IntPtr children;//GPtrArray*		
    };
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 8)]
    internal struct wz_stats_tree
    {
        public IntPtr filter;//char*
                             /* times */
        public double start;
        public double elapsed;
        public double now;

        public int st_flags;
        public int num_columns;
        public IntPtr display_name; //gchar*
        public IntPtr root; //wz_stat_node*
    };
    #endregion
    #region frame info
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 8)]
    internal struct wz_frame_info
    {
        public uint frameNum;
        public double time;
        public IntPtr srcAddress;
        public IntPtr dstAddress;
        public IntPtr protocol;
        public uint length;
        public IntPtr keyInfo;
    }
    #endregion
    #region simple tree
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 8)]
    internal struct wz_simple_treenode
    {
        public IntPtr name; //char*
        public IntPtr abbrev;//char*
        public IntPtr children;//GPtrArray*		
    }
    #endregion
    #region protocol hierarchy
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 8)]
    internal struct wz_phs_t
    {
        public IntPtr sibling;
        public IntPtr child;
        public IntPtr parent;
        public IntPtr filter;//char*
        public int protocol;
        public IntPtr proto_name;//chart*
        public uint frames;
        public ulong bytes;
    };
    #endregion
    #region simple table
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 8)]
    internal struct wz_simple_table
    {
        public IntPtr name;//char*
        public IntPtr filter;//char*
        public IntPtr columns;//GPtrArray*
        public IntPtr subTables;//GPtrArray*
    };
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 8)]
    internal struct _wz_simple_subtable
    {
        public IntPtr name;//char*
        public IntPtr Rows;//GPtrArray*
    };
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 8)]
    internal struct _wz_simple_field
    {
        public double n_value;
        public IntPtr string_value;//char*
    };
    public enum simple_field_type
    {
        TABLE_ITEM_NONE = 0,
        TABLE_ITEM_UINT,
        TABLE_ITEM_INT,
        TABLE_ITEM_STRING,
        TABLE_ITEM_FLOAT,
        TABLE_ITEM_ENUM
    };
    #endregion
    #region SRT
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 8)]
    internal struct wz_srt_table
    {
        public IntPtr type;//char* 
        public IntPtr filter;//char* 
        public IntPtr Rows;//GPtrArray*
    };
    [Serializable]
    [DataContract()]
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 8)]
    public struct wz_srt_row
    {
        [XmlIgnore][DataMember] public IntPtr procedure;//char*
        [DataMember] public uint samples;
        [DataMember] public int minSec;
        [DataMember] public int minnSec;
        [DataMember] public int maxSec;
        [DataMember] public int maxnSec;
        [DataMember] public int avgSec;
        [DataMember] public int avgnSec;
        [DataMember] public int sumSec;
        [DataMember] public int sumnSec;
    };
    #endregion
    #region RTD
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 8)]
    public struct rtd_stat_table
    #region
    {
        public IntPtr filter;//char*
        public uint num_rtds;              /**< number of elements on time_stats array */
        public IntPtr time_stats; //rtd_timestat* 
    };
    #endregion
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 8)]
    public struct rtd_timestat
    #region
    {
        public uint num_timestat;              /**< number of elements on rtd array */
        public IntPtr rtd; //timestat_t*
        public uint open_req_num;
        public uint disc_rsp_num;
        public uint req_dup_num;
        public uint rsp_dup_num;
    };
    #endregion
    [Serializable]
    [DataContract()]
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 8)]
    public struct timestat_t
    #region
    {
        [DataMember] public uint num;    /* number of samples */
        [DataMember] public uint min_num; /* frame number of minimum */
        [DataMember] public uint max_num; /* frame number of maximum */
        [DataMember] public nstime_t min;
        [DataMember] public nstime_t max;
        [DataMember] public nstime_t tot;
        [DataMember] public double variance;
    };
    #endregion
    #endregion
    #region sip stat
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 8)]
    internal struct wz_sip_stat
    {
        public IntPtr filter;//char* 
        public uint packets;     /* number of sip packets, including continuations */
        public uint resent_packets;
        public uint average_setup_time;
        public uint max_setup_time;
        public uint min_setup_time;
        public IntPtr RequestArray;//wz_sip_stats_item GPtrArray*
        public IntPtr ResponseArray;//wz_sip_stats_item array
    };
    [Serializable]
    [DataContract()]
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 8)]
    public struct wz_sip_stat_item
    {
        [DataMember] [MarshalAs(UnmanagedType.LPStr)] public string name; //const char*
        [DataMember] public uint code;
        [DataMember] public uint packets;     /* number of sip packets, including continuations */
        [DataMember] public uint resent_packets;
        [DataMember] public uint average_setup_time;
        [DataMember] public uint max_setup_time;
        [DataMember] public uint min_setup_time;
    };
    #endregion
    #region Sctp
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 8)]
    public struct wz_sctp
    {
        public uint totalPackeks;
        public IntPtr Items;//GPtrArray*
    };
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 8)]
    internal struct wz_sctp_item
    {
        public IntPtr srcAddr;
        public IntPtr destAddr;
        public ushort sport;
        public ushort dport;
        public uint Data;
        public uint Sack;
        public uint HBeat;
        public uint HBeatAck;
        public uint Init;
        public uint InitAck;
        public uint Cookie;
        public uint CookieAck;
        public uint Abort;
        public uint Error;
    };
    #endregion
    #region wsp
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 8)]
    public struct wz_wsp
    {
        public IntPtr WSP;//GPtrArray*
        public IntPtr ReplyPackets;//GPtrArray*
    };
    [Serializable]
    [DataContract()]
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 8)]
    public struct wz_wsp_item
    {
        [DataMember] [MarshalAs(UnmanagedType.LPStr)] public string pduType;//const char*
        [DataMember] public uint packets;
    };
    [Serializable]
    [DataContract()]
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 8)]
    public struct wz_wsp_reply_item
    {
        [DataMember] public int StatusCode;
        [DataMember] public uint packets;
        [DataMember] [MarshalAs(UnmanagedType.LPStr)] public string Descript;//char* 
    };
    #endregion
    #region LTE RLC
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 8)]
    internal struct wz_rlc_lte
    {
        public ushort number_of_ues;
        public uint total_frames;

        public uint bcch_frames;
        public uint bcch_bytes;
        public uint pcch_frames;
        public uint pcch_bytes;

        public IntPtr Rows;//GPtrArray* 
    };
    [Serializable]
    [DataContract()]
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 8)]
    public struct wz_rlc_lte_row_data
    {
        /* Key for matching this row */
        [DataMember] public ushort ueid;

        [DataMember] public int is_predefined_data;//gboolean 

        [DataMember] public uint UL_frames;
        [DataMember] public uint UL_total_bytes;
        public nstime_t UL_time_start;
        public nstime_t UL_time_stop;
        [DataMember] public uint UL_total_acks;
        [DataMember] public uint UL_total_nacks;
        [DataMember] public uint UL_total_missing;

        [DataMember] public uint DL_frames;
        [DataMember] public uint DL_total_bytes;
        public nstime_t DL_time_start;
        public nstime_t DL_time_stop;
        [DataMember] public uint DL_total_acks;
        [DataMember] public uint DL_total_nacks;
        [DataMember] public uint DL_total_missing;

        [DataMember] public double UL_bw;
        [DataMember] public double DL_bw;
    };
    #endregion
    #region LTE MAC
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 8)]
    internal struct wz_mac_lte
    {
        public ushort max_ul_ues_in_tti;
        public uint max_dl_ues_in_tti;

        public uint mib_frames;
        public uint sib_frames;
        public uint sib_bytes;
        public uint pch_frames;
        public uint pch_bytes;
        public uint pch_paging_ids;
        public uint rar_frames;
        public uint rar_entries;
        public ushort number_of_ues;
        public ushort number_of_rntis;
        public ushort number_of_ueids;

        public IntPtr Rows;
    };
    [Serializable]
    [DataContract()]
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 8)]
    public struct wz_mac_lte_row_data
    {
        [DataMember] public ushort rnti;
        [DataMember] public byte rnti_type;
        [DataMember] public ushort ueid;

        [DataMember] public int is_predefined_data;

        [DataMember] public uint UL_frames;
        [DataMember] public uint UL_raw_bytes;   /* all bytes */
        [DataMember] public uint UL_total_bytes; /* payload */
        nstime_t UL_time_start;
        nstime_t UL_time_stop;
        [DataMember] public uint UL_padding_bytes;
        [DataMember] public uint UL_CRC_errors;
        [DataMember] public uint UL_retx_frames;

        [DataMember] public uint DL_frames;
        [DataMember] public uint DL_raw_bytes;   /* all bytes */
        [DataMember] public uint DL_total_bytes;
        nstime_t DL_time_start;
        nstime_t DL_time_stop;
        [DataMember] public uint DL_padding_bytes;

        [DataMember] public uint DL_CRC_failures;
        [DataMember] public uint DL_CRC_high_code_rate;
        [DataMember] public uint DL_CRC_PDSCH_lost;
        [DataMember] public uint DL_CRC_Duplicate_NonZero_RV;
        [DataMember] public uint DL_retx_frames;

        [DataMember] public double DL_Pad;
        [DataMember] public double UL_Pad;
        [DataMember] public double UL_bw;
        [DataMember] public double DL_bw;
    };
    #endregion
    #region io,stat
    internal enum IoStatCalcType
    {
        CALC_TYPE_FRAMES = 0,
        CALC_TYPE_BYTES = 1,
        CALC_TYPE_FRAMES_AND_BYTES = 2,
        CALC_TYPE_COUNT = 3,
        CALC_TYPE_SUM = 4,
        CALC_TYPE_MIN = 5,
        CALC_TYPE_MAX = 6,
        CALC_TYPE_AVG = 7,
        CALC_TYPE_LOAD = 8,
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 8)]
    public struct wz_io_stat_t
    {
        public ulong interval;     /* The user-specified time interval (us) */
        public ulong duration;     /* The user-specified time interval (us) */
        public uint invl_prec;     /* Decimal precision of the time interval (1=10s, 2=100s etc) */
        public int num_cols;         /* The number of columns of stats in the table */
        public IntPtr items; //struct _io_stat_item_t *items;  /* Each item is a single cell in the table */
        public long start_time;    /* Time of first frame matching the filter */
        public IntPtr filters; //const char** filters; /* 'io,stat' cmd strings (e.g., "AVG(smb.time)smb.time") */
    };
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 8)]
    public struct wz_io_stat_item_t
    {
        public IntPtr parent;// io_stat_t* parent;
        public IntPtr next;// struct _io_stat_item_t *next;
        public IntPtr prev;// struct _io_stat_item_t *prev;
        public ulong start_time;   /* Time since start of capture (us)*/
        public int calc_type;        /* The statistic type */
        public int colnum;           /* Column number of this stat (0 to n) */
        public int hf_index;
        public uint frames;
        public uint num;          /* The sample size of a given statistic (only needed for AVG) */
        public ulong counter;      /* The accumulated data for the calculation of that statistic */
        public float float_counter;
        public double double_counter;
    };
    #endregion
    #region RTP
    [Serializable]
    [DataContract()]
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 8)]
    public struct wz_rtp_stream
    {
        [DataMember] [MarshalAs(UnmanagedType.LPStr)] public string src_addr;//char*
        [DataMember] public uint src_port;
        [DataMember] [MarshalAs(UnmanagedType.LPStr)] public string dst_addr;//char*
        [DataMember] public uint dest_port;
        [DataMember] public uint ssrc;
        [DataMember] [MarshalAs(UnmanagedType.LPStr)] public string payload_type;//char*
        [DataMember] public uint packet_count;
        [DataMember] public int lost;
        [DataMember] public double perc;
        [DataMember] public double max_delta;
        [DataMember] public double max_jitter;
        [DataMember] public double mean_jitter;
        [DataMember] public int problem;//gboolean
        [XmlIgnore] public IntPtr packets;//GPtrArray*
    };
    [Serializable]
    [DataContract()]
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 8)]
    public struct wz_rtp_Packet
    {
        [DataMember] public long time;       /** Unit is ticks */
        [DataMember] public uint PacketIndex;
        [DataMember] public uint sequence;
        [DataMember] public double delta;
        [DataMember] public double jitter;
        [DataMember] public double skew;
        [DataMember] public double bandwidth;
        [DataMember] public int problem;

        [DataMember] public uint delta_timestamp;
        [DataMember] public byte info_padding_count;
    }
    #endregion
    #region VoIP
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 8)]
    internal struct wz_voip_calls_info
    {
        //[MarshalAs(UnmanagedType.LPStr)]
        public IntPtr call_state;
        public IntPtr call_id;
        public IntPtr from_identity;
        public IntPtr to_identity;
        public IntPtr initial_speaker;
        public uint npackets;
        public IntPtr protocol_name;
        public IntPtr call_comment;
        public ushort call_num;

        /**> The frame_data struct holds the frame number and timing information needed. */
        public IntPtr start_fd;//frame_data
        public double start_rel_ts;
        public IntPtr stop_fd;//frame_data
        public double stop_rel_ts;
    };
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 8)]
    internal struct wz_seq_analysis_item
    {
        public uint frame_number;
        public IntPtr src_addr;//gchar*
        public ushort port_src;
        public IntPtr dst_addr;
        public ushort port_dst;
        public IntPtr frame_label;                 /**< the label on top of the arrow */
        public IntPtr time_str;                    /**< timestamp */
        public IntPtr comment;                     /**< a comment that appears at the right of the graph */
        public ushort conv_num;                   /**< The conversation number. Used for coloring VoIP calls. */
        public IntPtr protocol;                    /**< the label of the protocol defined in the IP packet */
    };
    #endregion
    #region string follow
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 8)]
    internal struct wz_follow_record_t
    {
        public int is_server;//gboolean
        public uint packet_num;
        public uint seq; /* TCP only */
        public IntPtr data;//GByteArray*
    };
    #endregion
    #region protocol preference
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 8)]
    public struct wz_Proto_Pref
    {
        public IntPtr name;//gchar*
        public IntPtr module;//module_t*
        public IntPtr children;//GPtrArray*
    };
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 8)]
    public struct wz_PCappreference
    {
        public IntPtr pref;
        public IntPtr title;//const char*   /**< title to use in GUI */
        public int type;                        /**< type of that preference */
        public uint value;
        public int tobase;
        public IntPtr stringValue;
        public IntPtr enumvals;//const enum_val_t* 
        public int radio_buttons; //gboolean
    };
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 8)]
    public struct wz_pref_enum_val_t
    {
        public IntPtr name;// const char* name;
        public IntPtr description; // const char* description;
        public int value;
    };
    #endregion
    #region expert info
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 8)]
    public struct wz_expert_entry
    {
        public uint group;
        public int frequency;
        public IntPtr protocol;//const gchar*
        public IntPtr summary;//gchar* 

        public IntPtr groupStr;//gchar* 
        public IntPtr Packets;//GPtrArray* 
    };
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 8)]
    public struct wz_expert_packet
    {
        public uint num;
        public IntPtr KeyInfo;//char* 
    };
    #endregion

    public class PCapLoadResult
    {
        public byte[] MetricDataList { set; get; }
        public PCapStatLoadResult StatResult { set; get; }
    }
    [Serializable]
    [DataContract()]
    public class PCapStatLoadResult
    {
        [DataMember] public SerializableDictionary<string, List<ConversationItem>> dictConv { set; get; }
        [DataMember] public SerializableDictionary<string, List<EndpointItem>> dictEndpoint { set; get; }
        [DataMember] public SerializableDictionary<string, RtdStatTable> dictRtd { set; get; }
        [DataMember] public List<Stat_Tree> listTree { set; get; }
        [DataMember] public List<ProtocolHierarchyNode> Protocols { set; get; }
        [DataMember] public List<Stat_SimpleTable> listSimpleTable { set; get; }
        [DataMember] public List<Stat_SrtTable> listSrtTable { set; get; }
        [DataMember] public Stat_SIP Stat_Sip { set; get; }
        [DataMember] public Stat_Sctp Stat_Sctp { set; get; }
        [DataMember] public Stat_Wsp Stat_Wsp { set; get; }
        [DataMember] public Stat_Rlc_LTE Stat_Rlc_LTE { set; get; }
        [DataMember] public Stat_Mac_LTE Stat_Mac_LTE { set; get; }
        [DataMember] public List<Rtp_stream> list_RtpStream { set; get; }
        [DataMember] public byte[] MetricData { set; get; } //MetricData
        [DataMember] public List<Voip_calls_info> list_VoIP_Calls { set; get; }
        [DataMember] public List<Seq_analysis_item> List_VoIP_Seqence { set; get; }
        [DataMember] public List<Follow_record> List_FollowRecords { set; get; }
        [DataMember] public List<expert_entry> List_ExpertInfo { set; get; }
    }

    [XmlRoot("dictionary")]
    public class SerializableDictionary<TKey, TValue> : Dictionary<TKey, TValue>, IXmlSerializable
    {
        public SerializableDictionary() { }
        public SerializableDictionary(IDictionary<TKey, TValue> dictionary) : base(dictionary) { }
        public SerializableDictionary(IDictionary<TKey, TValue> dictionary, IEqualityComparer<TKey> comparer) : base(dictionary, comparer) { }
        public SerializableDictionary(IEqualityComparer<TKey> comparer) : base(comparer) { }
        public SerializableDictionary(int capacity) : base(capacity) { }
        public SerializableDictionary(int capacity, IEqualityComparer<TKey> comparer) : base(capacity, comparer) { }

        #region IXmlSerializable Members
        public System.Xml.Schema.XmlSchema GetSchema()
        {
            return null;
        }

        public void ReadXml(System.Xml.XmlReader reader)
        {
            XmlSerializer keySerializer = new XmlSerializer(typeof(TKey));
            XmlSerializer valueSerializer = new XmlSerializer(typeof(TValue));

            bool wasEmpty = reader.IsEmptyElement;
            reader.Read();

            if (wasEmpty)
                return;

            while (reader.NodeType != System.Xml.XmlNodeType.EndElement)
            {
                reader.ReadStartElement("item");

                reader.ReadStartElement("key");
                TKey key = (TKey)keySerializer.Deserialize(reader);
                reader.ReadEndElement();

                reader.ReadStartElement("value");
                TValue value = (TValue)valueSerializer.Deserialize(reader);
                reader.ReadEndElement();

                this.Add(key, value);

                reader.ReadEndElement();
                reader.MoveToContent();
            }
            reader.ReadEndElement();
        }

        public void WriteXml(System.Xml.XmlWriter writer)
        {
            XmlSerializer keySerializer = new XmlSerializer(typeof(TKey));
            XmlSerializer valueSerializer = new XmlSerializer(typeof(TValue));

            foreach (TKey key in this.Keys)
            {
                writer.WriteStartElement("item");

                writer.WriteStartElement("key");
                keySerializer.Serialize(writer, key);
                writer.WriteEndElement();

                writer.WriteStartElement("value");
                TValue value = this[key];
                valueSerializer.Serialize(writer, value);
                writer.WriteEndElement();

                writer.WriteEndElement();
            }
        }
        #endregion
    }

    [Serializable]
    [DataContract]
    public class PacketInfo
    #region
    {
        [DataMember] public long Time { set; get; }
        [DataMember] public int FilePosition { set; get; }

        [DataMember] public string KeyInfo { set; get; }
        [DataMember] public PcapMessageInfo PCapInfo { set; get; }
    }
    #endregion
    [Serializable]
    [DataContract]
    public class PcapMessageInfo
    #region
    {
        [DataMember] public string SourceIp { set; get; }
        [DataMember] public string DestIp { set; get; }
        [DataMember] public string Protocol { set; get; }
        [DataMember] public short Length { set; get; }
    }
    #endregion

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 8)]
    public struct fvalue_t
    #region
    {
        public IntPtr ftype;
        public uint len;
    };
    #endregion
}
