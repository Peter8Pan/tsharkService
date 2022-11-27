using System;
using System.IO;
using System.Collections;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.ServiceModel;

namespace tsharkService
{
    [ServiceContract]
    public interface InterfaceSharkService
    {
        [OperationContract()] int Ping();
        [OperationContract()] byte[] LoadPacketList(string szPcapFileName);
        [OperationContract()] byte[] LoadPacketDetail(string szPcapFileName, uint frameNum);

        [OperationContract()] byte[] LoadSingleFileMetrics(string szPcapFileName, long deviceId,
            List<string> listFields, List<byte> listLoadFlags, bool useFrameIndex, string szFilter, out List<string> listMsg);
        [OperationContract()] byte[] LoadStatistics(string szPcapFileName, long deviceId, List<string> listCmd);

        [OperationContract()] byte[] Collect_Preferences();
        [OperationContract()] void Update_module_pref(IntPtr module, IntPtr pref, uint value, string stringValue);
        [OperationContract()] void Apply_all_pref();
    }
}
