using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.Serialization;

namespace tsharkService
{
    public class Enums
    {
        /* field types */
        public enum ftenum : int
        #region
        {
            FT_NONE,	/* used for text labels with no value */
            FT_PROTOCOL,
            FT_BOOLEAN,	/* TRUE and FALSE come from <glib.h> */
            FT_UINT8,
            FT_UINT16,
            FT_UINT24,	/* really a UINT32, but displayed as 6 hex-digits if FD_HEX*/
            FT_UINT32,
            FT_UINT40,	/* really a UINT64, but displayed as 10 hex-digits if FD_HEX*/
            FT_UINT48,	/* really a UINT64, but displayed as 12 hex-digits if FD_HEX*/
            FT_UINT56,	/* really a UINT64, but displayed as 14 hex-digits if FD_HEX*/
            FT_UINT64,
            FT_INT8,
            FT_INT16,
            FT_INT24,	/* same as for UINT24 */
            FT_INT32,
            FT_INT40, /* same as for UINT40 */
            FT_INT48, /* same as for UINT48 */
            FT_INT56, /* same as for UINT56 */
            FT_INT64,
            FT_IEEE_11073_SFLOAT,
            FT_IEEE_11073_FLOAT,
            FT_FLOAT,
            FT_DOUBLE,
            FT_ABSOLUTE_TIME,
            FT_RELATIVE_TIME,
            FT_STRING,
            FT_STRINGZ,	/* for use with proto_tree_add_item() */
            FT_UINT_STRING,	/* for use with proto_tree_add_item() */
            FT_ETHER,
            FT_BYTES,
            FT_UINT_BYTES,
            FT_IPv4,
            FT_IPv6,
            FT_IPXNET,
            FT_FRAMENUM,	/* a UINT32, but if selected lets you go to frame with that number */
            FT_PCRE,	/* a compiled Perl-Compatible Regular Expression object */
            FT_GUID,	/* GUID, UUID */
            FT_OID,		/* OBJECT IDENTIFIER */
            FT_EUI64,
            FT_AX25,
            FT_VINES,
            FT_REL_OID,	/* RELATIVE-OID */
            FT_SYSTEM_ID,
            FT_STRINGZPAD,	/* for use with proto_tree_add_item() */
            FT_FCWWN,
            FT_NUM_TYPES /* last item number plus one */
        };
        #endregion
        /* Types of port numbers Wireshark knows about. */
        [Serializable]
        [DataContract()]
        public enum port_type
        #region
        {
            [EnumMemberAttribute] PT_NONE,            /* no port number */
            [EnumMemberAttribute] PT_SCTP,            /* SCTP */
            [EnumMemberAttribute] PT_TCP,             /* TCP */
            [EnumMemberAttribute] PT_UDP,             /* UDP */
            [EnumMemberAttribute] PT_DCCP,            /* DCCP */
            [EnumMemberAttribute] PT_IPX,             /* IPX sockets */
            [EnumMemberAttribute] PT_NCP,             /* NCP connection */
            [EnumMemberAttribute] PT_EXCHG,           /* Fibre Channel exchange */
            [EnumMemberAttribute] PT_DDP,             /* DDP AppleTalk connection */
            [EnumMemberAttribute] PT_SBCCS,           /* FICON */
            [EnumMemberAttribute] PT_IDP,             /* XNS IDP sockets */
            [EnumMemberAttribute] PT_TIPC,            /* TIPC PORT */
            [EnumMemberAttribute] PT_USB,             /* USB endpoint 0xffff means the host */
            [EnumMemberAttribute] PT_I2C,
            [EnumMemberAttribute] PT_IBQP,            /* Infiniband QP number */
            [EnumMemberAttribute] PT_BLUETOOTH,
            [EnumMemberAttribute] PT_TDMOP
        } ;
        #endregion

        public enum wz_output_type
        #region
        {
            OUTPUT_FRAME_SUMMARY = 0x01,
            OUTPUT_FIELD_VALUE = 0x02,
            OUTPUT_STAT = 0x04,
            OUTPUT_FRAME_DETAIL = 0x08,
        }
        #endregion

        public enum StatView { None, Conversation, Endpoint, GeneralTree, GeneralSpread, TelephonyTree, TelephonySpread, ProtocolHierarchy, AnalysisView,
            TelephonySpread_Rtp, TelephonySpread_VoIP
        }
        public enum StatisticsType
        {
            None, ExpertInfo, Conversation, Endpoint, GeneralTree, TelephonyStat, SRT, RTD, SimpleTable,
            LTE_RLC, LTE_MAC, ProtocolHierarchy, PacketLen, SIP, SCTP, WSP, H225, RTP, VoIP,
        }
        public enum DataType
        {
            None,
            Byte, Short, Int, Long, Float, String, ByteArray,
        }
    }
}
