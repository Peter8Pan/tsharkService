using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.Serialization;
using System.Diagnostics;
using System.Collections;
using System.Xml.Serialization;

namespace tsharkService
{
    [Serializable]
    [DataContract()]
    public class MetricDataCollection
    {
        [DataMember()] public List<string> Cmd;
        [DataMember()] public List<MetricData> Data;
    }
    [Serializable]
    [DataContract()]
    public class MetricData
    {
        [DataMember()]public List<long> TimeList = new List<long>();
        [DataMember()]public List<MetricDataColumn> DataColumns = new List<MetricDataColumn>();
        public MetricData() { }
    }
    [Serializable]
    [DataContract()]
    public class MetricDataColumn
    {
        [DataMember()] public string MetricDbName { set; get; }
        [DataMember()] public Enums.DataType DataTypeEnum { set; get; }

        [DataMember()] public List<byte?> ByteList = new List<byte?>();
        [DataMember()] public List<short?> ShortList = new List<short?>();
        [DataMember()] public List<int?> IntList = new List<int?>();
        [DataMember()] public List<long?> LongList = new List<long?>();
        [DataMember()] public List<float?> FloatList = new List<float?>();
        [DataMember()] public List<string> StringList = new List<string>();
        [XmlIgnore] public List<ArrayList> ArrayListList = null;
        public MetricDataColumn() { }
        public void Add(object value)
        {
            switch (this.DataTypeEnum)
            {
                case Enums.DataType.Byte: { if (value != null && byte.TryParse(value.ToString(), out var tmp)) this.ByteList.Add(tmp); else this.ByteList.Add(null); break; }
                case Enums.DataType.Short: { if (value != null && short.TryParse(value.ToString(), out var tmp)) this.ShortList.Add(tmp); else this.ShortList.Add(null); break; }
                case Enums.DataType.Int: { if (value != null && int.TryParse(value.ToString(), out var tmp)) this.IntList.Add(tmp); else this.IntList.Add(null); break; }
                case Enums.DataType.ByteArray:
                case Enums.DataType.Long: { if (value != null && long.TryParse(value.ToString(), out var tmp)) this.LongList.Add(tmp); else this.LongList.Add(null); break; }
                case Enums.DataType.Float: { if (value != null && float.TryParse(value.ToString(), out var tmp)) this.FloatList.Add(tmp); else this.FloatList.Add(null); break; }
                case Enums.DataType.String: this.StringList.Add(value == null ? null : value.ToString()); break;
                default: Debug.Assert(false); break;
            }
        }
    }
}
