using System;
using System.Xml;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Xml.Serialization;
using System.Runtime.Serialization.Formatters.Binary;

namespace tsharkService
{
    class SharkService : InterfaceSharkService
    {
        public static int PointerSize = Environment.Is64BitProcess ? 8 : 4;
        public int Ping() => tsharkWrapper.PointerSize;
        public byte[] LoadPacketList(string szPcapFileName)
        {
            var loadParm = new Structures.wz_LoadParameters()
            {
                cmdCount = 0,
                fieldCount = 0,
                ShallCreateProtocolTree = 0,
                FrameIndexInsteadOfTime = 0,
                filter = IntPtr.Zero
            };
            loadParm.cf_name = Marshal.StringToHGlobalAnsi(szPcapFileName);
            loadParm.outputFlag = (int)Enums.wz_output_type.OUTPUT_FRAME_SUMMARY;

            IntPtr pLoadParm = Marshal.AllocHGlobal(Marshal.SizeOf(loadParm));
            Marshal.StructureToPtr(loadParm, pLoadParm, false);
            IntPtr pLoadResult=IntPtr.Zero;

            try
            {
                pLoadResult = tsharkWrapper.wz_LoadPcapFile(pLoadParm);
                if (pLoadResult != IntPtr.Zero)
                {
                    var loadResult = (Structures.LoadResult)Marshal.PtrToStructure(pLoadResult,
                               typeof(Structures.LoadResult));
                    if (loadResult.FrameSummary == IntPtr.Zero)
                        return null;

                    var summaryArray = (Structures.GArray)Marshal.PtrToStructure(loadResult.FrameSummary, typeof(Structures.GArray));
                    if (summaryArray.len == 0)
                        return null;

                    using (var ms = new MemoryStream())
                    using (var writer = new StreamWriter(ms))
                    {
                        for (int m = 0; m < summaryArray.len * tsharkWrapper.PointerSize; m += tsharkWrapper.PointerSize)
                        {
                            var frameInfo = (Structures.wz_frame_info)Marshal.PtrToStructure(
                                Marshal.ReadIntPtr(summaryArray.data, m), typeof(Structures.wz_frame_info));

                            writer.WriteLine((long)(frameInfo.time * TimeSpan.TicksPerSecond));
                            writer.WriteLine((int)frameInfo.frameNum + 1);
                            writer.WriteLine(Marshal.PtrToStringAnsi(frameInfo.keyInfo).Replace("â†’", "->"));
                            writer.WriteLine(Marshal.PtrToStringAnsi(frameInfo.srcAddress));
                            writer.WriteLine(Marshal.PtrToStringAnsi(frameInfo.dstAddress));
                            writer.WriteLine(Marshal.PtrToStringAnsi(frameInfo.protocol));
                            writer.WriteLine(frameInfo.length);
                        }
                        writer.Flush();
                        return ms.ToArray();
                    }
                }
            }
            catch
            {
            }
            finally
            {
                Marshal.FreeHGlobal(loadParm.cf_name);
                Marshal.FreeHGlobal(pLoadParm);
                if (pLoadResult != IntPtr.Zero)
                    tsharkWrapper.wz_Free_LoadResult(pLoadResult);
            }
            return null;
        }
        public byte[] LoadPacketDetail(string szPcapFileName, uint frameNum)
        {
            var loadParm = new Structures.wz_LoadParameters()
            {
                cmdCount = 0,
                fieldCount = 0,
                ShallCreateProtocolTree = 1,
                FrameIndexInsteadOfTime = 0,
                filter = IntPtr.Zero,
            };
            loadParm.cf_name = Marshal.StringToHGlobalAnsi(szPcapFileName);
            loadParm.outputFlag = (int)Enums.wz_output_type.OUTPUT_FRAME_DETAIL;
            loadParm.frameNumber = frameNum;

            IntPtr pLoadParm = Marshal.AllocHGlobal(Marshal.SizeOf(loadParm));
            Marshal.StructureToPtr(loadParm, pLoadParm, false);
            IntPtr pLoadResult = IntPtr.Zero;

            try
            {
                pLoadResult = tsharkWrapper.wz_LoadPcapFile(pLoadParm);
                if (pLoadResult == IntPtr.Zero)
                    return null;

                var loadResult = (Structures.LoadResult)Marshal.PtrToStructure(pLoadResult, typeof(Structures.LoadResult));
                if (loadResult.Simple_Treenode == IntPtr.Zero)
                    return null;

                var treeRoot = (Structures.wz_simple_treenode)Marshal.PtrToStructure(loadResult.Simple_Treenode, typeof(Structures.wz_simple_treenode));
                if (treeRoot.children != IntPtr.Zero)
                {
                    using (var ms = new MemoryStream())
                    using (var writer = new StreamWriter(ms))
                    {
                        DisplayPcapTreeNodeArray(treeRoot.children, 0, writer);

                        if (treeRoot.abbrev != IntPtr.Zero)
                        {
                            var byteArray = (Structures.GArray)Marshal.PtrToStructure(treeRoot.abbrev, typeof(Structures.GArray));
                            //root.bytes = new List<byte>();
                            //unsafe
                            //{
                            //    byte* src = (byte*)byteArray.data;
                            //    for (int m = 0; m < byteArray.len; ++m)
                            //        root.bytes.Add(*src++);
                            //}
                        }
                        writer.Flush();
                        return ms.ToArray();
                    }
                }
                return null;

                void DisplayPcapTreeNodeArray(IntPtr children, int level, StreamWriter writer)
                {
                    var treeNodeArray = (Structures.GArray)Marshal.PtrToStructure(children, typeof(Structures.GArray));
                    if (treeNodeArray.len == 0)
                        return;

                    for (int m = 0; m < treeNodeArray.len * tsharkWrapper.PointerSize; m += tsharkWrapper.PointerSize)
                    {
                        var wzNode = (Structures.wz_simple_treenode)Marshal.PtrToStructure(Marshal.ReadIntPtr(treeNodeArray.data, m), typeof(Structures.wz_simple_treenode));
                        if (wzNode.name == IntPtr.Zero)
                            continue;

                        writer.WriteLine(level);
                        writer.WriteLine(Marshal.PtrToStringAnsi(wzNode.name));
                        writer.WriteLine(Marshal.PtrToStringAnsi(wzNode.abbrev));

                        if (wzNode.children == IntPtr.Zero)
                            continue;

                        DisplayPcapTreeNodeArray(wzNode.children, level + 1, writer);
                    }
                }
            }
            catch
            {
            }
            finally
            {
                Marshal.FreeHGlobal(loadParm.cf_name);
                Marshal.FreeHGlobal(pLoadParm);
                if (pLoadResult != IntPtr.Zero)
                    tsharkWrapper.wz_Free_LoadResult(pLoadResult);
            }
            return null;
        }

        public byte[] LoadSingleFileMetrics(string szPcapFileName, long deviceId,
            List<string> listFields, List<byte> listLoadFlags, bool useFrameIndex, string szFilter, out List<string> listMsg)
        {
            listMsg = null;
            var loadParm = new Structures.wz_LoadParameters()
            {
                cmdCount = 0,
                fieldCount = 0,
                ShallCreateProtocolTree = 1,
                FrameIndexInsteadOfTime = (byte)(useFrameIndex ? 1 : 0),
                filter = IntPtr.Zero,
            };
            if (string.IsNullOrEmpty(szFilter) == false)
                loadParm.filter = Marshal.StringToHGlobalAnsi(szFilter);
            loadParm.cf_name = Marshal.StringToHGlobalAnsi(szPcapFileName);
            loadParm.outputFlag = (int)Enums.wz_output_type.OUTPUT_FIELD_VALUE;

            loadParm.fieldCount = listFields.Count;
            listFields.Sort(); //make the field with same protocol contingent
            IntPtr[] outFields = new IntPtr[listFields.Count];
            for (int m = 0; m < listFields.Count; ++m)
                outFields[m] = Marshal.StringToHGlobalAnsi(listFields[m]);
            loadParm.requestedFields = Marshal.AllocHGlobal(tsharkWrapper.PointerSize * listFields.Count);
            Marshal.Copy(outFields, 0, loadParm.requestedFields, listFields.Count);

            byte[] byLoadFlags = listLoadFlags.ToArray();
            loadParm.requestedFieldLoadFlags = Marshal.AllocHGlobal(byLoadFlags.Length);
            Marshal.Copy(byLoadFlags, 0, loadParm.requestedFieldLoadFlags, byLoadFlags.Length);

            //System.Diagnostics.Debugger.Launch();
            return tsharkWrapper.LoadFile(szPcapFileName, deviceId, loadParm, listFields, listLoadFlags, out listMsg)?.MetricDataList;
        }
        public byte[] LoadStatistics(string szPcapFileName, long deviceId, List<string> listCmd)
        {
            try
            {
                var statParm = new Structures.StatParameter()
                {
                    CmdType = "ws",
                    PipeName = $"P_{DateTime.Now.Ticks}",
                    PcapFileName = szPcapFileName,
                    DeviceId = deviceId,
                    ListCmd = listCmd,
                };
                var loadParm = new Structures.wz_LoadParameters()
                {
                    cmdCount = 0,
                    fieldCount = 0,
                    ShallCreateProtocolTree = 0,
                    FrameIndexInsteadOfTime = 0,
                    filter = IntPtr.Zero,
                };
                loadParm.cf_name = Marshal.StringToHGlobalAnsi(statParm.PcapFileName);
                loadParm.outputFlag = (int)Enums.wz_output_type.OUTPUT_STAT;

                loadParm.ShallCreateProtocolTree = statParm.ListCmd.Contains("io,phs") || statParm.ListCmd.Contains("plen,tree")
                    || statParm.ListCmd.Contains("sip,stat") || statParm.ListCmd.FindIndex(f => f.StartsWith("io,stat")) >= 0
                    || statParm.ListCmd.Contains("VoIP,Calls") || statParm.ListCmd.FindIndex(f => f.StartsWith("follow,")) >= 0
                    ? 1 : 0;

                loadParm.cmdCount = statParm.ListCmd.Count;
                statParm.ListCmd.Sort();
                IntPtr[] outCmds = new IntPtr[statParm.ListCmd.Count];
                for (int m = 0; m < statParm.ListCmd.Count; ++m)
                    outCmds[m] = Marshal.StringToHGlobalAnsi(statParm.ListCmd[m]);

                loadParm.requestedCmds = Marshal.AllocHGlobal(tsharkWrapper.PointerSize * statParm.ListCmd.Count);
                Marshal.Copy(outCmds, 0, loadParm.requestedCmds, statParm.ListCmd.Count);

                var pResult = tsharkWrapper.LoadFile(statParm.PcapFileName, deviceId, loadParm, statParm.ListCmd, null, out var listMsg);
                if (pResult == null || pResult.StatResult == null)
                    return null;

                //System.Diagnostics.Debugger.Launch();
                //using (var ms = new MemoryStream())
                //{
                //    var formatter = new BinaryFormatter();
                //    formatter.Serialize(ms, pResult.StatResult);
                //    return ms.ToArray();
                //}
                using (var ms = new MemoryStream())
                {
                    new XmlSerializer(typeof(Structures.PCapStatLoadResult)).Serialize(ms, pResult.StatResult);
                    return ms.ToArray();
                }
            }
            catch
            {

            }
            return null;
        }

        public byte[] Collect_Preferences()
        {
            try
            {
                //System.Diagnostics.Debugger.Launch();
                var pTree = tsharkWrapper.wz_Collect_Preferences();
                using (var ms = new MemoryStream())
                using (var xmlOut = new XmlTextWriter(ms, Encoding.Default))
                {
                    xmlOut.Formatting = Formatting.Indented;
                    xmlOut.WriteStartDocument();

                    FillTree(pTree, xmlOut);
                    xmlOut.WriteEndDocument();
                    xmlOut.Flush();
                    return ms.ToArray();
                }
            }
            catch
            {

            }
            return null;

            void FillTree(IntPtr parentIntPtr, XmlTextWriter xmlOut)
            {
                if (parentIntPtr == IntPtr.Zero)
                    return;

                var treeArray = (Structures.GArray)Marshal.PtrToStructure(parentIntPtr, typeof(Structures.GArray));
                xmlOut.WriteStartElement("Node");
                {
                    xmlOut.WriteAttributeString("Count", treeArray.len.ToString());
                    for (int m = 0; m < treeArray.len; ++m)
                    {
                        xmlOut.WriteStartElement("Item");
                        {
                            IntPtr pItem = Marshal.ReadIntPtr(treeArray.data, m * tsharkWrapper.PointerSize);
                            if (pItem != IntPtr.Zero)
                            {
                                var wItem = (Structures.wz_Proto_Pref)Marshal.PtrToStructure(pItem, typeof(Structures.wz_Proto_Pref));
                                xmlOut.WriteAttributeString("Name", Marshal.PtrToStringAnsi(wItem.name));

                                if (wItem.module != IntPtr.Zero)
                                {
                                    xmlOut.WriteStartElement("Module");
                                    {
                                        xmlOut.WriteAttributeString("Ptr", wItem.module.ToInt64().ToString());
                                        DumpMode(wItem.module, xmlOut);
                                    }
                                    xmlOut.WriteEndElement();
                                }
                                if (wItem.children != IntPtr.Zero)
                                    FillTree(wItem.children, xmlOut);
                            }
                        }
                        xmlOut.WriteEndElement();
                    }
                }
                xmlOut.WriteEndElement();
            }
            void DumpMode(IntPtr module, XmlTextWriter xmlOut)
            {
                var pArray = tsharkWrapper.wz_Collect_Module_Preferences(module);
                if (pArray == IntPtr.Zero)
                    return;

                var prefArray = (Structures.GArray)Marshal.PtrToStructure(pArray, typeof(Structures.GArray));
                unsafe
                {
                    xmlOut.WriteAttributeString("Count", prefArray.len.ToString());
                    for (int m = 0; m < prefArray.len; ++m)
                    {
                        xmlOut.WriteStartElement("Item");
                        {
                            IntPtr pItem = Marshal.ReadIntPtr(prefArray.data, m * tsharkWrapper.PointerSize);
                            if (pItem == IntPtr.Zero)
                                continue;

                            var wItem = (Structures.wz_PCappreference)Marshal.PtrToStructure(pItem, typeof(Structures.wz_PCappreference));
                            xmlOut.WriteAttributeString("Type", wItem.type.ToString());
                            xmlOut.WriteAttributeString("Ptr", wItem.pref.ToInt64().ToString());
                            switch (wItem.type)
                            {
                                case 0x01:// PREF_UINT   
                                case 0x08:// PREF_STRING
                                    #region
                                    {
                                        xmlOut.WriteAttributeString("Title", Marshal.PtrToStringAnsi(wItem.title));
                                        if (wItem.type == 0x01)
                                            xmlOut.WriteAttributeString("Value", Convert.ToString(wItem.value, wItem.tobase));
                                        else if (wItem.stringValue != IntPtr.Zero)
                                            xmlOut.WriteAttributeString("Value", Marshal.PtrToStringAnsi(wItem.stringValue));
                                        break;
                                    }
                                #endregion
                                case 0x02:// PREF_BOOL
                                    #region
                                    {
                                        xmlOut.WriteAttributeString("Title", Marshal.PtrToStringAnsi(wItem.title));
                                        xmlOut.WriteAttributeString("Value", wItem.value.ToString());
                                        break;
                                    }
                                #endregion
                                case 0x04:// PREF_ENUM
                                    #region
                                    {
                                        xmlOut.WriteAttributeString("Title", Marshal.PtrToStringAnsi(wItem.title));

                                        var szSelected = string.Empty;
                                        var sourcePtr = (Structures.wz_pref_enum_val_t*)wItem.enumvals;
                                        for (int i = 0; i < 200; ++i)
                                        {
                                            var item = *sourcePtr++;
                                            if (item.name == IntPtr.Zero)
                                                break;

                                            xmlOut.WriteStartElement("Opt");
                                            {
                                                xmlOut.WriteAttributeString("Name", $"[{item.value}]: " + Marshal.PtrToStringAnsi(item.description));
                                                xmlOut.WriteAttributeString("Value", wItem.value.ToString());
                                            }
                                            xmlOut.WriteEndElement();
                                        }
                                        break;
                                    }
                                #endregion
                                case 0x10:// PREF_RANGE
                                    break;
                                case 0x20:// PREF_STATIC_TEXT
                                    break;
                                case 0x40:// PREF_UAT
                                    break;
                                case 0x80:// PREF_FILENAME
                                    break;
                                case 0x100:// PREF_COLOR
                                    break;
                                case 0x200:// PREF_CUSTOM
                                    break;
                                case 0x400:// PREF_OBSOLETE
                                    break;
                                case 0x800:// PREF_DIRNAME
                                    break;
                            }
                        }
                        xmlOut.WriteEndElement();
                    }
                }
            }
        }
        public void Update_module_pref(IntPtr module, IntPtr pref, uint value, string stringValue)
        {
            try
            {
                tsharkWrapper.wz_update_module_pref(module, pref, value,
                stringValue == null ? IntPtr.Zero : Marshal.StringToCoTaskMemAnsi(stringValue));
            }
            catch { }
        }
        public void Apply_all_pref()
        {
            try
            {
                tsharkWrapper.wz_apply_all_pref();
            }
            catch { }
        }
    }
}
