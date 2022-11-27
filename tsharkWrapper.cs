using System;
using System.IO;
using System.IO.Compression;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Runtime.CompilerServices;

namespace tsharkService
{
    public class tsharkWrapper
    {
        public const string DLLFileName = @"tshark.dll";
        //public const string WiresharkDll = @"libwireshark.dll";
        static public int PointerSize = Environment.Is64BitProcess ? 8 : 4;

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool SetDllDirectory(string lpPathName);
        [DllImport("kernel32.dll", BestFitMapping = false, ThrowOnUnmappableChar = true)]
        public static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPStr)] string fileName);
        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool FreeLibrary(IntPtr hModule);

        static IntPtr WiresharkDllHandle = IntPtr.Zero;
        public static void RegisterWireshark(string execPath)
        {
            wz_Initialize(execPath);
        }
        public static void UnRegisterWireshark()
        {
            wz_Free_EntireWiresharkResource();
            if (WiresharkDllHandle != IntPtr.Zero)
                FreeLibrary(WiresharkDllHandle);
        }
        
        [DllImport(DLLFileName, EntryPoint = "wz_Initialize", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        static extern int wz_Initialize(string szDllDir);

        [DllImport(DLLFileName, EntryPoint = "wz_Free_EntireWiresharkResource", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        public static extern void wz_Free_EntireWiresharkResource();

        [DllImport(DLLFileName, EntryPoint = "wz_LoadPcapFile", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr wz_LoadPcapFile( //LoadResult*
            IntPtr loadParameters); //wz_LoadParameters*

        [DllImport(DLLFileName, EntryPoint = "wz_G_Free", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        public static extern void wz_G_Free(IntPtr pData);
        [DllImport(DLLFileName, EntryPoint = "wz_g_byte_array_free", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        public static extern void wz_g_byte_array_free(IntPtr pData);
        [DllImport(DLLFileName, EntryPoint = "wz_g_ptr_array_free", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        public static extern void wz_g_ptr_array_free(IntPtr pData);
        [DllImport(DLLFileName, EntryPoint = "wz_Free_LoadResult", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        public static extern void wz_Free_LoadResult(IntPtr pLoadResult); //LoadResult* pLoadResult
        [DllImport(DLLFileName, EntryPoint = "wz_Free_LoadResultOfField", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        public static extern void wz_Free_LoadResultOfField(IntPtr pLoadResult, int fieldIndex);

        [DllImport(DLLFileName, EntryPoint = "wz_address_to_str", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr wz_address_to_str(IntPtr addr, int resolveName);

        [DllImport(DLLFileName, EntryPoint = "wz_GetProtocolFieldNames", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr wz_GetProtocolFieldNames(ref int arrayLength);
        [DllImport(DLLFileName, EntryPoint = "wz_Free_GetProtocolFieldNames", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        public static extern void wz_Free_GetProtocolFieldNames(IntPtr pointer);
        [DllImport(DLLFileName, EntryPoint = "wz_IsLayer3", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        public static extern int wz_IsLayer3(IntPtr szName);

        [DllImport(DLLFileName, EntryPoint = "wz_Collect_Preferences", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr wz_Collect_Preferences();//GPtrArray*
        [DllImport(DLLFileName, EntryPoint = "wz_Collect_Module_Preferences", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr wz_Collect_Module_Preferences(IntPtr module);//GPtrArray*
        [DllImport(DLLFileName, EntryPoint = "wz_update_module_pref", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        public static extern void wz_update_module_pref(IntPtr module, IntPtr pref, uint value, IntPtr stringValue);
        [DllImport(DLLFileName, EntryPoint = "wz_apply_all_pref", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        public static extern void wz_apply_all_pref();

        static object WiresharkLocker = new object();
        static public Structures.PCapLoadResult LoadFile(string szPcapFileName, long deviceId,
            Structures.wz_LoadParameters loadParm, List<string> listFieldOrCmd, List<byte> listLoadFlags, out List<string> listMsg)
        {
            lock (WiresharkLocker)
            {
                listMsg = new List<string>();
                var pcapResultData = new Structures.PCapLoadResult();

                IntPtr pLoadParm = Marshal.AllocHGlobal(Marshal.SizeOf(loadParm));
                Marshal.StructureToPtr(loadParm, pLoadParm, false);
                IntPtr pLoadResult = IntPtr.Zero;
                try
                {
                    pLoadResult = tsharkWrapper.wz_LoadPcapFile(pLoadParm);
                    if (pLoadResult == null || pLoadResult == IntPtr.Zero)
                        return null;

                    var loadResult = (Structures.LoadResult)Marshal.PtrToStructure(pLoadResult, typeof(Structures.LoadResult));
                    if (loadResult.errorInfo != null && loadResult.errorInfo != IntPtr.Zero)
                    #region
                    {
                        var errInfo = (Structures.GArray)Marshal.PtrToStructure(loadResult.errorInfo, typeof(Structures.GArray));
                        if (errInfo.len > 0)
                        {
                            for (int m = 0; m < errInfo.len; ++m)
                                listMsg.Add(Marshal.PtrToStringAuto(Marshal.ReadIntPtr(errInfo.data, m * PointerSize)));
                            return null;
                        }
                    }
                    #endregion

                    if ((loadParm.outputFlag & (int)Enums.wz_output_type.OUTPUT_FIELD_VALUE) > 0 && loadResult.FieldCount > 0)
                    #region
                    {
                        using (var ms = new MemoryStream())
                        using (var writer = new StreamWriter(ms))
                        {
                            int[] arrDataType = new int[loadResult.FieldCount];
                            Marshal.Copy(loadResult.output_field_ftype, arrDataType, 0, loadResult.FieldCount);
                            //data: 10000100000, each digit represend a field and 1 means the starting of a protocol
                            byte[] arrFieldNeedIndex = new byte[loadResult.FieldCount];
                            Marshal.Copy(loadResult.FieldNeedIndexArray, arrFieldNeedIndex, 0, loadResult.FieldCount);

                            for (int fieldIndex = 0; fieldIndex < loadResult.FieldCount; ++fieldIndex)
                            #region field
                            {
                                if (arrFieldNeedIndex[fieldIndex] == 0)//go to the field which is the starting of a protocol 
                                    continue;

                                var indexDot = listFieldOrCmd[fieldIndex].IndexOf('.');
                                writer.WriteLine("@" + listFieldOrCmd[fieldIndex].Substring(0, indexDot));
                                for (; fieldIndex < loadResult.FieldCount; ++fieldIndex)
                                {
                                    if (arrFieldNeedIndex[fieldIndex] == 1)
                                    {
                                        #region frame index
                                        IntPtr pFrameIndexArray = Marshal.ReadIntPtr(loadResult.FieldIndexArrays, fieldIndex * PointerSize);
                                        if (pFrameIndexArray == IntPtr.Zero)
                                            break;

                                        var frameIndexArray = (Structures.GArray)Marshal.PtrToStructure(pFrameIndexArray, typeof(Structures.GArray));
                                        unsafe
                                        {
                                            var sourcePtr = (Int64*)frameIndexArray.data;
                                            writer.WriteLine(frameIndexArray.len);
                                            for (int i = 0; i < frameIndexArray.len; ++i)
                                                writer.WriteLine((long)*sourcePtr++);
                                        }
                                        #endregion
                                    }

                                    IntPtr pDataArray = Marshal.ReadIntPtr(loadResult.FieldDataArrays, fieldIndex * PointerSize);
                                    if (pDataArray == IntPtr.Zero)
                                        continue;

                                    #region
                                    var dataArray = (Structures.GArray)Marshal.PtrToStructure(pDataArray, typeof(Structures.GArray));
                                    if (dataArray.len == 0)
                                        continue;

                                    try
                                    {
                                        writer.WriteLine("#" + listFieldOrCmd[fieldIndex]);
                                        var isArray = listLoadFlags[fieldIndex] == 0;
                                        writer.WriteLine(isArray ? "1" : "0");
                                        //if (isArray) //is array
                                        //    metricDataColumn.ArrayListList = new List<System.Collections.ArrayList>();

                                        switch ((Enums.ftenum)arrDataType[fieldIndex])
                                        {
                                            case Enums.ftenum.FT_NONE:
                                            case Enums.ftenum.FT_UINT8:
                                                #region
                                                {
                                                    writer.WriteLine(Enums.DataType.Byte.ToString());
                                                    unsafe
                                                    {
                                                        var count = dataArray.len;
                                                        writer.WriteLine(count);
                                                        if (isArray == false)
                                                        {
                                                            var sourcePtr = (byte*)dataArray.data;
                                                            for (int i = 0; i < count; ++i)
                                                                writer.WriteLine(*sourcePtr++);
                                                        }
                                                        else
                                                        {
                                                            for (int k = 0; k < count; ++k)
                                                            {
                                                                var valArray = (Structures.GArray)Marshal.PtrToStructure(Marshal.ReadIntPtr(dataArray.data, k * PointerSize), typeof(Structures.GArray));
                                                                var sourcePtr = (byte*)valArray.data;
                                                                for (int i = 0; i < valArray.len; ++i)
                                                                {
                                                                    writer.Write(*sourcePtr++); writer.Write(";");
                                                                }
                                                                writer.WriteLine();
                                                            }
                                                        }
                                                    }
                                                    break;
                                                }
                                            #endregion
                                            case Enums.ftenum.FT_UINT16:
                                                #region
                                                {
                                                    writer.WriteLine(Enums.DataType.Int.ToString());
                                                    unsafe
                                                    {
                                                        var count = dataArray.len;
                                                        writer.WriteLine(count);
                                                        if (isArray == false)
                                                        {
                                                            var sourcePtr = (ushort*)dataArray.data;
                                                            for (int i = 0; i < count; ++i)
                                                                writer.WriteLine(*sourcePtr++);
                                                        }
                                                        else
                                                        {
                                                            for (int k = 0; k < count; ++k)
                                                            {
                                                                var valArray = (Structures.GArray)Marshal.PtrToStructure(Marshal.ReadIntPtr(dataArray.data, k * PointerSize), typeof(Structures.GArray));
                                                                var sourcePtr = (ushort*)valArray.data;
                                                                for (int i = 0; i < valArray.len; ++i)
                                                                {
                                                                    writer.Write(*sourcePtr++); writer.Write(";");
                                                                }
                                                                writer.WriteLine();
                                                            }
                                                        }
                                                    }
                                                    break;
                                                }
                                            #endregion
                                            case Enums.ftenum.FT_UINT24:
                                            case Enums.ftenum.FT_UINT32:
                                                #region
                                                {
                                                    writer.WriteLine(Enums.DataType.Long.ToString());
                                                    unsafe
                                                    {
                                                        var count = dataArray.len;
                                                        writer.WriteLine(count);
                                                        if (isArray == false)
                                                        {
                                                            var sourcePtr = (uint*)dataArray.data;
                                                            for (int i = 0; i < count; ++i)
                                                                writer.WriteLine(*sourcePtr++);
                                                        }
                                                        else
                                                        {
                                                            for (int k = 0; k < count; ++k)
                                                            {
                                                                var valArray = (Structures.GArray)Marshal.PtrToStructure(Marshal.ReadIntPtr(dataArray.data, k * PointerSize), typeof(Structures.GArray));
                                                                var sourcePtr = (uint*)valArray.data;
                                                                for (int i = 0; i < valArray.len; ++i)
                                                                {
                                                                    writer.Write(*sourcePtr++); writer.Write(";");
                                                                }
                                                                writer.WriteLine();
                                                            }
                                                        }
                                                    }
                                                    break;
                                                }
                                            #endregion
                                            case Enums.ftenum.FT_UINT40:
                                            case Enums.ftenum.FT_UINT48:
                                            case Enums.ftenum.FT_UINT56:
                                            case Enums.ftenum.FT_UINT64:
                                                #region
                                                {
                                                    writer.WriteLine(Enums.DataType.Long.ToString());
                                                    unsafe
                                                    {
                                                        var count = dataArray.len;
                                                        writer.WriteLine(count);
                                                        if (isArray == false)
                                                        {
                                                            var sourcePtr = (ulong*)dataArray.data;
                                                            for (int i = 0; i < count; ++i)
                                                                writer.WriteLine((long)*sourcePtr++);
                                                        }
                                                        else
                                                        {
                                                            for (int k = 0; k < count; ++k)
                                                            {
                                                                var valArray = (Structures.GArray)Marshal.PtrToStructure(Marshal.ReadIntPtr(dataArray.data, k * PointerSize), typeof(Structures.GArray));
                                                                var sourcePtr = (ulong*)valArray.data;
                                                                for (int i = 0; i < valArray.len; ++i)
                                                                {
                                                                    writer.Write(*sourcePtr++); writer.Write(";");
                                                                }
                                                                writer.WriteLine();
                                                            }
                                                        }
                                                    }
                                                    break;
                                                }
                                            #endregion
                                            case Enums.ftenum.FT_INT8:
                                                #region
                                                {
                                                    writer.WriteLine(Enums.DataType.Short.ToString());
                                                    unsafe
                                                    {
                                                        var count = dataArray.len;
                                                        writer.WriteLine(count);
                                                        if (isArray == false)
                                                        {
                                                            var sourcePtr = (sbyte*)dataArray.data;
                                                            for (int i = 0; i < count; ++i)
                                                                writer.WriteLine(*sourcePtr++);
                                                        }
                                                        else
                                                        {
                                                            for (int k = 0; k < count; ++k)
                                                            {
                                                                var valArray = (Structures.GArray)Marshal.PtrToStructure(Marshal.ReadIntPtr(dataArray.data, k * PointerSize), typeof(Structures.GArray));
                                                                var sourcePtr = (sbyte*)valArray.data;
                                                                for (int i = 0; i < valArray.len; ++i)
                                                                {
                                                                    writer.Write(*sourcePtr++); writer.Write(";");
                                                                }
                                                                writer.WriteLine();
                                                            }
                                                        }
                                                    }
                                                    break;
                                                }
                                            #endregion
                                            case Enums.ftenum.FT_INT16:
                                                #region
                                                {
                                                    writer.WriteLine(Enums.DataType.Short.ToString());
                                                    unsafe
                                                    {
                                                        var count = dataArray.len;
                                                        writer.WriteLine(count);
                                                        if (isArray == false)
                                                        {
                                                            var sourcePtr = (short*)dataArray.data;
                                                            for (int i = 0; i < count; ++i)
                                                                writer.WriteLine(*sourcePtr++);
                                                        }
                                                        else
                                                        {
                                                            for (int k = 0; k < count; ++k)
                                                            {
                                                                var valArray = (Structures.GArray)Marshal.PtrToStructure(Marshal.ReadIntPtr(dataArray.data, k * PointerSize), typeof(Structures.GArray));
                                                                var sourcePtr = (short*)valArray.data;
                                                                for (int i = 0; i < valArray.len; ++i)
                                                                {
                                                                    writer.Write(*sourcePtr++); writer.Write(";");
                                                                }
                                                                writer.WriteLine();
                                                            }
                                                        }
                                                    }
                                                    break;
                                                }
                                            #endregion
                                            case Enums.ftenum.FT_INT24:
                                            case Enums.ftenum.FT_INT32:
                                                #region
                                                {
                                                    writer.WriteLine(Enums.DataType.Int.ToString());
                                                    unsafe
                                                    {
                                                        var count = dataArray.len;
                                                        writer.WriteLine(count);
                                                        if (isArray == false)
                                                        {
                                                            var sourcePtr = (int*)dataArray.data;
                                                            for (int i = 0; i < count; ++i)
                                                                writer.WriteLine(*sourcePtr++);
                                                        }
                                                        else
                                                        {
                                                            for (int k = 0; k < count; ++k)
                                                            {
                                                                var valArray = (Structures.GArray)Marshal.PtrToStructure(Marshal.ReadIntPtr(dataArray.data, k * PointerSize), typeof(Structures.GArray));
                                                                var sourcePtr = (int*)valArray.data;
                                                                for (int i = 0; i < valArray.len; ++i)
                                                                {
                                                                    writer.Write(*sourcePtr++); writer.Write(";");
                                                                }
                                                                writer.WriteLine();
                                                            }
                                                        }
                                                    }
                                                    break;
                                                }
                                            #endregion
                                            case Enums.ftenum.FT_INT40:
                                            case Enums.ftenum.FT_INT48:
                                            case Enums.ftenum.FT_INT56:
                                            case Enums.ftenum.FT_INT64:
                                            case Enums.ftenum.FT_ABSOLUTE_TIME:
                                            case Enums.ftenum.FT_RELATIVE_TIME:
                                                #region
                                                {
                                                    writer.WriteLine(Enums.DataType.Long.ToString());
                                                    var arrData = new long[dataArray.len];
                                                    unsafe
                                                    {
                                                        var count = dataArray.len;
                                                        writer.WriteLine(count);
                                                        if (isArray == false)
                                                        {
                                                            var sourcePtr = (long*)dataArray.data;
                                                            for (int i = 0; i < count; ++i)
                                                                writer.WriteLine(*sourcePtr++);
                                                        }
                                                        else
                                                        {
                                                            for (int k = 0; k < count; ++k)
                                                            {
                                                                var valArray = (Structures.GArray)Marshal.PtrToStructure(Marshal.ReadIntPtr(dataArray.data, k * PointerSize), typeof(Structures.GArray));
                                                                var sourcePtr = (long*)valArray.data;
                                                                for (int i = 0; i < valArray.len; ++i)
                                                                {
                                                                    writer.Write(*sourcePtr++); writer.Write(";");
                                                                }
                                                                writer.WriteLine();
                                                            }
                                                        }
                                                    }
                                                    break;
                                                }
                                            #endregion
                                            case Enums.ftenum.FT_FLOAT:
                                            case Enums.ftenum.FT_DOUBLE:
                                                #region
                                                {
                                                    writer.WriteLine(Enums.DataType.Float.ToString());
                                                    unsafe
                                                    {
                                                        var count = dataArray.len;
                                                        writer.WriteLine(count);
                                                        if (isArray == false)
                                                        {
                                                            var sourcePtr = (float*)dataArray.data;
                                                            for (int i = 0; i < count; ++i)
                                                                writer.WriteLine(*sourcePtr++);
                                                        }
                                                        else
                                                        {
                                                            for (int k = 0; k < count; ++k)
                                                            {
                                                                var valArray = (Structures.GArray)Marshal.PtrToStructure(Marshal.ReadIntPtr(dataArray.data, k * PointerSize), typeof(Structures.GArray));
                                                                var sourcePtr = (float*)valArray.data;
                                                                for (int i = 0; i < valArray.len; ++i)
                                                                {
                                                                    writer.Write(*sourcePtr++); writer.Write(";");
                                                                }
                                                                writer.WriteLine();
                                                            }
                                                        }
                                                    }
                                                    break;
                                                }
                                            #endregion
                                            case Enums.ftenum.FT_STRING:
                                            case Enums.ftenum.FT_STRINGZ:
                                            case Enums.ftenum.FT_UINT_STRING:
                                            case Enums.ftenum.FT_PROTOCOL:
                                                #region
                                                {
                                                    writer.WriteLine(Enums.DataType.String.ToString());
                                                    var count = dataArray.len;
                                                    writer.WriteLine(count);
                                                    if (isArray == false)
                                                    {
                                                        for (int i = 0; i < count; ++i)
                                                        {
                                                            writer.WriteLine(Marshal.PtrToStringAnsi(Marshal.ReadIntPtr(dataArray.data, i * PointerSize)));
                                                        }
                                                    }
                                                    else
                                                    {
                                                        for (int k = 0; k < count; ++k)
                                                        {
                                                            var valArray = (Structures.GArray)Marshal.PtrToStructure(Marshal.ReadIntPtr(dataArray.data, k * PointerSize), typeof(Structures.GArray));
                                                            for (int i = 0; i < valArray.len; ++i)
                                                            {
                                                                writer.Write(Marshal.PtrToStringAnsi(Marshal.ReadIntPtr(valArray.data, i * PointerSize)));
                                                                writer.Write(";");
                                                            }
                                                            writer.WriteLine();
                                                        }
                                                    }
                                                    break;
                                                }
                                            #endregion
                                            case Enums.ftenum.FT_BYTES:
                                                #region
                                                {
                                                    writer.WriteLine(Enums.DataType.ByteArray.ToString());
                                                    var arrData = new long[dataArray.len];
                                                    unsafe
                                                    {
                                                        var count = dataArray.len;
                                                        writer.WriteLine(count);
                                                        if (isArray == false)
                                                        {
                                                            for (int i = 0; i < count; ++i)
                                                            {
                                                                var byteArray = (Structures.GArray)Marshal.PtrToStructure(Marshal.ReadIntPtr(dataArray.data, i * PointerSize), typeof(Structures.GArray));
                                                                if (byteArray.len == 0)
                                                                    continue;

                                                                var sourcePtr = (byte*)byteArray.data;
                                                                for (int b = 0; b < byteArray.len; ++b)
                                                                { writer.Write(*sourcePtr++); writer.Write(","); }
                                                                writer.WriteLine();
                                                            }
                                                        }
                                                        else
                                                        {
                                                            for (int k = 0; k < count; ++k)
                                                            {
                                                                var valArray = (Structures.GArray)Marshal.PtrToStructure(Marshal.ReadIntPtr(dataArray.data, k * PointerSize), typeof(Structures.GArray));
                                                                for (int i = 0; i < count; ++i)
                                                                {
                                                                    var byteArray = (Structures.GArray)Marshal.PtrToStructure(Marshal.ReadIntPtr(valArray.data, i * PointerSize), typeof(Structures.GArray));
                                                                    if (byteArray.len == 0)
                                                                        continue;

                                                                    var sourcePtr = (byte*)byteArray.data;
                                                                    for (int b = 0; b < byteArray.len; ++b)
                                                                    { writer.Write(*sourcePtr++); writer.Write(","); }
                                                                    writer.WriteLine(";");
                                                                }
                                                                writer.WriteLine();
                                                            }
                                                        }
                                                    }
                                                    break;
                                                }
                                                #endregion
                                        }
                                    }
                                    finally
                                    {
                                        tsharkWrapper.wz_Free_LoadResultOfField(pLoadResult, fieldIndex);
                                    }
                                    #endregion

                                    if (fieldIndex + 1 >= loadResult.FieldCount || arrFieldNeedIndex[fieldIndex + 1] == 1) //next protocol
                                        break;
                                }
                            }
                            #endregion
                            writer.Flush();
                            pcapResultData.MetricDataList = ms.ToArray();
                        }
                    }
                    #endregion

                    if ((loadParm.outputFlag & (int)Enums.wz_output_type.OUTPUT_STAT) > 0)
                    {
                        pcapResultData.StatResult = new Structures.PCapStatLoadResult();
                        if (loadResult.Stat_ConvArray != IntPtr.Zero)
                        #region
                        {
                            pcapResultData.StatResult.dictConv = new Structures.SerializableDictionary<string, List<Structures.ConversationItem>>(StringComparer.OrdinalIgnoreCase);
                            unsafe
                            {
                                var typeArray = (Structures.GArray)Marshal.PtrToStructure(loadResult.Stat_ConvTypeArray, typeof(Structures.GArray));
                                var dataArray = (Structures.GArray)Marshal.PtrToStructure(loadResult.Stat_ConvArray, typeof(Structures.GArray));
                                for (int m = 0; m < dataArray.len; ++m)
                                {
                                    IntPtr pType = Marshal.ReadIntPtr(typeArray.data, m * PointerSize);
                                    IntPtr pItemArray = Marshal.ReadIntPtr(dataArray.data, m * PointerSize);
                                    if (pType == IntPtr.Zero || pItemArray == IntPtr.Zero)
                                        continue;

                                    var list = new List<Structures.ConversationItem>();
                                    var itemArray = (Structures.GArray)Marshal.PtrToStructure(pItemArray, typeof(Structures.GArray));
                                    var sourcePtr = (Structures.conv_item_t*)itemArray.data;
                                    for (int i = 0; i < itemArray.len; ++i)
                                    {
                                        var item = *sourcePtr++;
                                        list.Add(new Structures.ConversationItem(item));
                                    }
                                    pcapResultData.StatResult.dictConv[Marshal.PtrToStringAnsi(pType)] = list;
                                }
                            }
                        }
                        #endregion
                        if (loadResult.Stat_EndpointArray != IntPtr.Zero)
                        #region
                        {
                            pcapResultData.StatResult.dictEndpoint = new Structures.SerializableDictionary<string, List<Structures.EndpointItem>>(StringComparer.OrdinalIgnoreCase);
                            unsafe
                            {
                                var typeArray = (Structures.GArray)Marshal.PtrToStructure(loadResult.Stat_EndpointTypeArray, typeof(Structures.GArray));
                                var dataArray = (Structures.GArray)Marshal.PtrToStructure(loadResult.Stat_EndpointArray, typeof(Structures.GArray));
                                for (int m = 0; m < dataArray.len; ++m)
                                {
                                    IntPtr pType = Marshal.ReadIntPtr(typeArray.data, m * PointerSize);
                                    IntPtr pItemArray = Marshal.ReadIntPtr(dataArray.data, m * PointerSize);
                                    if (pType == IntPtr.Zero || pItemArray == IntPtr.Zero)
                                        continue;

                                    var list = new List<Structures.EndpointItem>();
                                    var itemArray = (Structures.GArray)Marshal.PtrToStructure(pItemArray, typeof(Structures.GArray));
                                    var sourcePtr = (Structures.hostlist_talker_t*)itemArray.data;
                                    for (int i = 0; i < itemArray.len; ++i)
                                    {
                                        var item = *sourcePtr++;
                                        list.Add(new Structures.EndpointItem(item));
                                    }
                                    pcapResultData.StatResult.dictEndpoint[Marshal.PtrToStringAnsi(pType)] = list;
                                }
                            }
                        }
                        #endregion
                        if (loadResult.Stat_RtdArray != IntPtr.Zero)
                        #region
                        {
                            pcapResultData.StatResult.dictRtd = new Structures.SerializableDictionary<string, Structures.RtdStatTable>(StringComparer.OrdinalIgnoreCase);
                            unsafe
                            {
                                var typeArray = (Structures.GArray)Marshal.PtrToStructure(loadResult.Stat_RtdTypeArray, typeof(Structures.GArray));
                                var dataArray = (Structures.GArray)Marshal.PtrToStructure(loadResult.Stat_RtdArray, typeof(Structures.GArray));
                                for (int m = 0; m < dataArray.len; ++m)
                                {
                                    IntPtr pType = Marshal.ReadIntPtr(typeArray.data, m * PointerSize);
                                    IntPtr pItemArray = Marshal.ReadIntPtr(dataArray.data, m * PointerSize);
                                    if (pType == IntPtr.Zero || pItemArray == IntPtr.Zero)
                                        continue;

                                    var table = (Structures.rtd_stat_table)Marshal.PtrToStructure(pItemArray, typeof(Structures.rtd_stat_table));
                                    var tableClass = new Structures.RtdStatTable();

                                    if (table.filter != IntPtr.Zero)
                                        tableClass.filter = (string)Marshal.PtrToStringAnsi(table.filter);
                                    for (int k = 0; k < table.num_rtds; ++k)
                                    {
                                        var item = (Structures.rtd_timestat)Marshal.PtrToStructure(Marshal.ReadIntPtr(table.time_stats, k * PointerSize), typeof(Structures.rtd_timestat));
                                        tableClass.time_stats.Add(new Structures.RtdTimestat(item));
                                    }
                                    pcapResultData.StatResult.dictRtd[Marshal.PtrToStringAnsi(pType)] = tableClass;
                                }
                            }
                        }
                        #endregion
                        if (loadResult.Stat_TreeArray != IntPtr.Zero)
                        #region
                        {
                            pcapResultData.StatResult.listTree = new List<Structures.Stat_Tree>();
                            unsafe
                            {
                                var dataArray = (Structures.GArray)Marshal.PtrToStructure(loadResult.Stat_TreeArray, typeof(Structures.GArray));
                                for (int m = 0; m < dataArray.len; ++m)
                                {
                                    IntPtr pItemArray = Marshal.ReadIntPtr(dataArray.data, m * PointerSize);
                                    if (pItemArray == IntPtr.Zero)
                                        continue;

                                    var item = (Structures.wz_stats_tree)Marshal.PtrToStructure(pItemArray, typeof(Structures.wz_stats_tree));
                                    pcapResultData.StatResult.listTree.Add(new Structures.Stat_Tree(item));
                                }
                            }
                        }
                        #endregion
                        if (loadResult.Stat_ProtocolHierarchy != IntPtr.Zero)
                        #region
                        {
                            pcapResultData.StatResult.Protocols = new List<Structures.ProtocolHierarchyNode>();
                            LoadNode(pcapResultData.StatResult.Protocols, loadResult.Stat_ProtocolHierarchy);
                            void LoadNode(List<Structures.ProtocolHierarchyNode> nodes, IntPtr wzNodePtr)
                            {
                                var wzNode = (Structures.wz_phs_t)Marshal.PtrToStructure(wzNodePtr, typeof(Structures.wz_phs_t));
                                if (wzNode.frames == 0)
                                    return;

                                var zeeNode = new Structures.ProtocolHierarchyNode(wzNode);
                                nodes.Add(zeeNode);

                                if (wzNode.child != IntPtr.Zero)
                                {
                                    zeeNode.Children = new List<Structures.ProtocolHierarchyNode>();
                                    LoadNode(zeeNode.Children, wzNode.child);
                                }
                                if (wzNode.sibling != IntPtr.Zero)
                                    LoadNode(nodes, wzNode.sibling);

                                tsharkWrapper.wz_G_Free(wzNodePtr);
                            }
                        }
                        #endregion
                        if (loadResult.Stat_SimpleTables != IntPtr.Zero)
                        #region
                        {
                            pcapResultData.StatResult.listSimpleTable = new List<Structures.Stat_SimpleTable>();
                            var dataArray = (Structures.GArray)Marshal.PtrToStructure(loadResult.Stat_SimpleTables, typeof(Structures.GArray));
                            for (int m = 0; m < dataArray.len; ++m)
                            {
                                IntPtr pItemArray = Marshal.ReadIntPtr(dataArray.data, m * PointerSize);
                                if (pItemArray == IntPtr.Zero)
                                    continue;

                                var table = (Structures.wz_simple_table)Marshal.PtrToStructure(pItemArray, typeof(Structures.wz_simple_table));
                                pcapResultData.StatResult.listSimpleTable.Add(new Structures.Stat_SimpleTable(table));
                            }
                        }
                        #endregion
                        if (loadResult.Stat_SrtTables != IntPtr.Zero)
                        #region
                        {
                            pcapResultData.StatResult.listSrtTable = new List<Structures.Stat_SrtTable>();
                            var dataArray = (Structures.GArray)Marshal.PtrToStructure(loadResult.Stat_SrtTables, typeof(Structures.GArray));
                            for (int m = 0; m < dataArray.len; ++m)
                            {
                                IntPtr pItemArray = Marshal.ReadIntPtr(dataArray.data, m * PointerSize);
                                if (pItemArray == IntPtr.Zero)
                                    continue;

                                var table = (Structures.wz_srt_table)Marshal.PtrToStructure(pItemArray, typeof(Structures.wz_srt_table));
                                pcapResultData.StatResult.listSrtTable.Add(new Structures.Stat_SrtTable(table));
                            }
                        }
                        #endregion
                        if (loadResult.Stat_SIP != IntPtr.Zero)
                        #region
                        {
                            var wz_sip_stat = (Structures.wz_sip_stat)Marshal.PtrToStructure(loadResult.Stat_SIP, typeof(Structures.wz_sip_stat));
                            pcapResultData.StatResult.Stat_Sip = new Structures.Stat_SIP(wz_sip_stat);
                        }
                        #endregion
                        if (loadResult.Stat_Sctp != IntPtr.Zero)
                        #region
                        {
                            pcapResultData.StatResult.Stat_Sctp = new Structures.Stat_Sctp();
                            var wz_sctp = (Structures.wz_sctp)Marshal.PtrToStructure(loadResult.Stat_Sctp, typeof(Structures.wz_sctp));
                            pcapResultData.StatResult.Stat_Sctp.totalPackeks = wz_sctp.totalPackeks;
                            pcapResultData.StatResult.Stat_Sctp.Items = new List<Structures.Sctp_item>();

                            var dataArray = (Structures.GArray)Marshal.PtrToStructure(wz_sctp.Items, typeof(Structures.GArray));
                            for (int m = 0; m < dataArray.len; ++m)
                            {
                                IntPtr pItemArray = Marshal.ReadIntPtr(dataArray.data, m * PointerSize);
                                if (pItemArray == IntPtr.Zero)
                                    continue;

                                var wItem = (Structures.wz_sctp_item)Marshal.PtrToStructure(pItemArray, typeof(Structures.wz_sctp_item));
                                pcapResultData.StatResult.Stat_Sctp.Items.Add(new Structures.Sctp_item(wItem));
                            }
                        }
                        #endregion
                        if (loadResult.Stat_Wsp != IntPtr.Zero)
                        #region
                        {
                            pcapResultData.StatResult.Stat_Wsp = new Structures.Stat_Wsp();

                            var wz_wsp = (Structures.wz_wsp)Marshal.PtrToStructure(loadResult.Stat_Wsp, typeof(Structures.wz_wsp));
                            var dataArray = (Structures.GArray)Marshal.PtrToStructure(wz_wsp.WSP, typeof(Structures.GArray));
                            for (int m = 0; m < dataArray.len; ++m)
                            {
                                IntPtr pItemArray = Marshal.ReadIntPtr(dataArray.data, m * PointerSize);
                                if (pItemArray == IntPtr.Zero)
                                    continue;

                                var wItem = (Structures.wz_wsp_item)Marshal.PtrToStructure(pItemArray, typeof(Structures.wz_wsp_item));
                                pcapResultData.StatResult.Stat_Wsp.WSP.Add(wItem);
                            }

                            dataArray = (Structures.GArray)Marshal.PtrToStructure(wz_wsp.ReplyPackets, typeof(Structures.GArray));
                            for (int m = 0; m < dataArray.len; ++m)
                            {
                                IntPtr pItemArray = Marshal.ReadIntPtr(dataArray.data, m * PointerSize);
                                if (pItemArray == IntPtr.Zero)
                                    continue;

                                var wItem = (Structures.wz_wsp_reply_item)Marshal.PtrToStructure(pItemArray, typeof(Structures.wz_wsp_reply_item));
                                pcapResultData.StatResult.Stat_Wsp.ReplyPackets.Add(wItem);
                            }
                        }
                        #endregion
                        if (loadResult.Stat_Rlc_LTE != IntPtr.Zero)
                        #region
                        {
                            var wz_rlc_lte = (Structures.wz_rlc_lte)Marshal.PtrToStructure(loadResult.Stat_Rlc_LTE, typeof(Structures.wz_rlc_lte));
                            pcapResultData.StatResult.Stat_Rlc_LTE = new Structures.Stat_Rlc_LTE(wz_rlc_lte);
                        }
                        #endregion
                        if (loadResult.Stat_Mac_LTE != IntPtr.Zero)
                        #region
                        {
                            var wz_mac_lte = (Structures.wz_mac_lte)Marshal.PtrToStructure(loadResult.Stat_Rlc_LTE, typeof(Structures.wz_mac_lte));
                            pcapResultData.StatResult.Stat_Mac_LTE = new Structures.Stat_Mac_LTE(wz_mac_lte);
                        }
                        #endregion
                        if (loadResult.Stat_io_stat_t != IntPtr.Zero)
                        #region
                        {
                            using (var ms = new MemoryStream())
                            using (var writer = new StreamWriter(ms))
                            {
                                unsafe
                                {
                                    bool timeDumped = false, doDumpTime = true;
                                    var wz_io_stat = (Structures.wz_io_stat_t)Marshal.PtrToStructure(loadResult.Stat_io_stat_t, typeof(Structures.wz_io_stat_t));
                                    var rowCount = (int)Math.Ceiling((double)wz_io_stat.duration / wz_io_stat.interval);
                                    for (int col = 0; col < wz_io_stat.num_cols; ++col)
                                    {
                                        if (timeDumped) doDumpTime = false;
                                        writer.WriteLine("#" + Marshal.PtrToStringAnsi(Marshal.ReadIntPtr(wz_io_stat.filters, col * PointerSize)));
                                        writer.WriteLine(doDumpTime ? "1" : "0");

                                        var itemPtr = new IntPtr(wz_io_stat.items.ToInt64() + col * sizeof(Structures.wz_io_stat_item_t));
                                        for (int row = 0; row <= (int)rowCount; ++row)
                                        {
                                            if (itemPtr == IntPtr.Zero)
                                                break;

                                            var columnItem = (Structures.wz_io_stat_item_t)Marshal.PtrToStructure(itemPtr, typeof(Structures.wz_io_stat_item_t));
                                            if (row == 0)
                                            #region
                                            {
                                                switch ((Structures.IoStatCalcType)columnItem.calc_type)
                                                {
                                                    case Structures.IoStatCalcType.CALC_TYPE_FRAMES:
                                                    case Structures.IoStatCalcType.CALC_TYPE_BYTES:
                                                    case Structures.IoStatCalcType.CALC_TYPE_FRAMES_AND_BYTES:
                                                    case Structures.IoStatCalcType.CALC_TYPE_COUNT: writer.WriteLine(Enums.DataType.Int.ToString()); break;
                                                    case Structures.IoStatCalcType.CALC_TYPE_SUM:
                                                    case Structures.IoStatCalcType.CALC_TYPE_MIN:
                                                    case Structures.IoStatCalcType.CALC_TYPE_MAX:
                                                    case Structures.IoStatCalcType.CALC_TYPE_AVG:
                                                        switch ((Enums.ftenum)columnItem.hf_index)
                                                        {
                                                            case Enums.ftenum.FT_FLOAT:
                                                            case Enums.ftenum.FT_DOUBLE: writer.WriteLine(Enums.DataType.Float.ToString()); break;
                                                            case Enums.ftenum.FT_RELATIVE_TIME: writer.WriteLine(Enums.DataType.Int.ToString()); break;
                                                            default: writer.WriteLine(Enums.DataType.Int.ToString()); break;
                                                        }
                                                        break;
                                                    case Structures.IoStatCalcType.CALC_TYPE_LOAD: writer.WriteLine(Enums.DataType.Int.ToString()); break;
                                                }
                                            }
                                            #endregion
                                            if (doDumpTime)
                                            {
                                                timeDumped = true;
                                                writer.WriteLine(1_000_000_0 * wz_io_stat.start_time + 10 * row * (long)wz_io_stat.interval); //Convert second to ticks
                                            }
                                            switch ((Structures.IoStatCalcType)columnItem.calc_type)
                                            {
                                                case Structures.IoStatCalcType.CALC_TYPE_FRAMES: writer.WriteLine(columnItem.frames); break;
                                                case Structures.IoStatCalcType.CALC_TYPE_BYTES: writer.WriteLine(columnItem.counter); break;
                                                case Structures.IoStatCalcType.CALC_TYPE_FRAMES_AND_BYTES: writer.WriteLine(columnItem.frames); break;
                                                case Structures.IoStatCalcType.CALC_TYPE_COUNT: writer.WriteLine(columnItem.counter); break;
                                                case Structures.IoStatCalcType.CALC_TYPE_SUM:
                                                case Structures.IoStatCalcType.CALC_TYPE_MIN:
                                                case Structures.IoStatCalcType.CALC_TYPE_MAX:
                                                    switch ((Enums.ftenum)columnItem.hf_index)
                                                    {
                                                        case Enums.ftenum.FT_FLOAT: writer.WriteLine(columnItem.float_counter); break;
                                                        case Enums.ftenum.FT_DOUBLE: writer.WriteLine(columnItem.double_counter); break;
                                                        case Enums.ftenum.FT_RELATIVE_TIME: writer.WriteLine(columnItem.counter); break;
                                                        default: writer.WriteLine(columnItem.counter); break;
                                                    }
                                                    break;
                                                case Structures.IoStatCalcType.CALC_TYPE_AVG:
                                                    switch ((Enums.ftenum)columnItem.hf_index)
                                                    {
                                                        case Enums.ftenum.FT_FLOAT: writer.WriteLine(columnItem.num == 0 ? columnItem.float_counter : columnItem.float_counter / columnItem.num); break;
                                                        case Enums.ftenum.FT_DOUBLE: writer.WriteLine(columnItem.num == 0 ? columnItem.double_counter : columnItem.double_counter / columnItem.num); break;
                                                        case Enums.ftenum.FT_RELATIVE_TIME: writer.WriteLine(columnItem.num == 0 ? columnItem.counter : columnItem.counter / columnItem.num); break;
                                                        default: writer.WriteLine(columnItem.num == 0 ? columnItem.counter : columnItem.counter / columnItem.num); break;
                                                    }
                                                    break;
                                                case Structures.IoStatCalcType.CALC_TYPE_LOAD:
                                                default:
                                                    writer.WriteLine();
                                                    break;
                                            }
                                            itemPtr = columnItem.next;
                                        }
                                    }
                                }
                                writer.Flush();
                                pcapResultData.StatResult.MetricData = ms.ToArray();
                            }
                        }
                        #endregion
                        if (loadResult.Stat_rtp_stat != IntPtr.Zero)
                        #region
                        {
                            pcapResultData.StatResult.list_RtpStream = new List<Structures.Rtp_stream>();
                            unsafe
                            {
                                var dataArray = (Structures.GArray)Marshal.PtrToStructure(loadResult.Stat_rtp_stat, typeof(Structures.GArray));
                                for (int m = 0; m < dataArray.len; ++m)
                                {
                                    IntPtr pItem = Marshal.ReadIntPtr(dataArray.data, m * PointerSize);
                                    if (pItem == IntPtr.Zero)
                                        continue;

                                    var wItem = (Structures.wz_rtp_stream)Marshal.PtrToStructure(pItem, typeof(Structures.wz_rtp_stream));
                                    var packets = new List<Structures.wz_rtp_Packet>();
                                    pcapResultData.StatResult.list_RtpStream.Add(new Structures.Rtp_stream() { Data = wItem, packets = packets });

                                    var packetArray = (Structures.GArray)Marshal.PtrToStructure(wItem.packets, typeof(Structures.GArray));
                                    for (int p = 0; p < packetArray.len; ++p)
                                    {
                                        IntPtr packetPtr = Marshal.ReadIntPtr(packetArray.data, p * PointerSize);
                                        if (packetPtr == IntPtr.Zero)
                                            continue;

                                        var packet = (Structures.wz_rtp_Packet)Marshal.PtrToStructure(packetPtr, typeof(Structures.wz_rtp_Packet));
                                        packets.Add(packet);
                                    }
                                }
                            }
                        }
                        #endregion
                        if (loadResult.Stat_VoIP_Calls != IntPtr.Zero)
                        #region
                        {
                            pcapResultData.StatResult.list_VoIP_Calls = new List<Structures.Voip_calls_info>();
                            //unsafe
                            {
                                var dataArray = (Structures.GArray)Marshal.PtrToStructure(loadResult.Stat_VoIP_Calls, typeof(Structures.GArray));
                                for (int m = 0; m < dataArray.len; ++m)
                                {
                                    IntPtr pItem = Marshal.ReadIntPtr(dataArray.data, m * PointerSize);
                                    if (pItem == IntPtr.Zero)
                                        continue;

                                    var wItem = (Structures.wz_voip_calls_info)Marshal.PtrToStructure(pItem, typeof(Structures.wz_voip_calls_info));
                                    var info = new Structures.Voip_calls_info(wItem);
                                    pcapResultData.StatResult.list_VoIP_Calls.Add(info);
                                }
                            }

                            pcapResultData.StatResult.List_VoIP_Seqence = new List<Structures.Seq_analysis_item>();
                            //unsafe
                            {
                                var dataArray = (Structures.GArray)Marshal.PtrToStructure(loadResult.List_VoIP_Seqence, typeof(Structures.GArray));
                                for (int m = 0; m < dataArray.len; ++m)
                                {
                                    IntPtr pItem = Marshal.ReadIntPtr(dataArray.data, m * PointerSize);
                                    if (pItem == IntPtr.Zero)
                                        continue;

                                    var wItem = (Structures.wz_seq_analysis_item)Marshal.PtrToStructure(pItem, typeof(Structures.wz_seq_analysis_item));
                                    var info = new Structures.Seq_analysis_item(wItem);
                                    pcapResultData.StatResult.List_VoIP_Seqence.Add(info);
                                }
                            }
                        }
                        #endregion
                        if (loadResult.List_FollowRecords != IntPtr.Zero)
                        #region
                        {
                            pcapResultData.StatResult.List_FollowRecords = new List<Structures.Follow_record>();
                            unsafe
                            {
                                var dataArray = (Structures.GArray)Marshal.PtrToStructure(loadResult.List_FollowRecords, typeof(Structures.GArray));
                                for (int m = 0; m < dataArray.len; ++m)
                                {
                                    IntPtr pItem = Marshal.ReadIntPtr(dataArray.data, m * PointerSize);
                                    if (pItem == IntPtr.Zero)
                                        continue;

                                    var wItem = (Structures.wz_follow_record_t)Marshal.PtrToStructure(pItem, typeof(Structures.wz_follow_record_t));
                                    pcapResultData.StatResult.List_FollowRecords.Add(new Structures.Follow_record(wItem));
                                }
                            }
                        }
                        #endregion
                        if (loadResult.List_ExpertInfo != IntPtr.Zero)
                        #region
                        {
                            unsafe
                            {
                                pcapResultData.StatResult.List_ExpertInfo = new List<Structures.expert_entry>();
                                string[] arrSeverity = { "Error", "Warning", "Note", "Chat" };
                                var dataArray = (Structures.GArray)Marshal.PtrToStructure(loadResult.List_ExpertInfo, typeof(Structures.GArray));
                                for (int g = 0; g < dataArray.len && g < 4; ++g)
                                {
                                    IntPtr pItem = Marshal.ReadIntPtr(dataArray.data, g * PointerSize);
                                    if (pItem == IntPtr.Zero)
                                        continue;

                                    var entryAray = (Structures.GArray)Marshal.PtrToStructure(pItem, typeof(Structures.GArray));
                                    Structures.wz_expert_entry* pEntry = (Structures.wz_expert_entry*)entryAray.data;
                                    for (int e = 0; e < entryAray.len; ++e)
                                    {
                                        pcapResultData.StatResult.List_ExpertInfo.Add(new Structures.expert_entry(*pEntry) { Severity = arrSeverity[g] });
                                        pEntry++;
                                    }
                                }
                            }
                        }
                        #endregion
                    }
                }
                catch 
                {
                }
                finally
                {
                    try
                    {
                        Marshal.FreeHGlobal(loadParm.cf_name);
                        Marshal.FreeHGlobal(loadParm.requestedFields);
                        Marshal.FreeHGlobal(loadParm.requestedFieldLoadFlags);
                        Marshal.FreeHGlobal(pLoadParm);
                        if (pLoadResult != IntPtr.Zero)
                            tsharkWrapper.wz_Free_LoadResult(pLoadResult);
                    }
                    catch { }
                }
                return pcapResultData;
            }
        }
        private static unsafe String MarshalUnsafeCStringToString(IntPtr ptr, Encoding encoding)
        {
            void* rawPointer = ptr.ToPointer();
            if (rawPointer == null) return "";

            char* unsafeCString = (char*)rawPointer;

            int lengthOfCString = 0;
            while (unsafeCString[lengthOfCString] != '\0')
            {
                lengthOfCString++;
            }

            // now that we have the length of the string, let's get its size in bytes
            int lengthInBytes = encoding.GetByteCount(unsafeCString, lengthOfCString);
            byte[] asByteArray = new byte[lengthInBytes];

            fixed (byte* ptrByteArray = asByteArray)
            {
                encoding.GetBytes(unsafeCString, lengthOfCString, ptrByteArray, lengthInBytes);
            }

            // now get the string
            return encoding.GetString(asByteArray);
        }
        static void FetchSchemaFromWireshark()
        {
            //int arrayLength = 0;
            //IntPtr intPtrNameArray = tsharkWrapper.wz_GetProtocolFieldNames(ref arrayLength);
            //try
            //{
            //    bool bStartWrite = false;
            //    var charListHandled = new List<char>();
            //    char currentChar = ' ';
            //    using (ZipArchive archive = ZipFile.Open(Common.Config.LocalConfigHelper.GetFilePath(Common.Enums.ConfigurationType.Wireshark_Schema), ZipArchiveMode.Create))
            //    {
            //        StreamWriter writer = null;
            //        var totalLength = arrayLength * Global.Instance.PointerSize;
            //        for (int m = 0; m < totalLength; m += Global.Instance.PointerSize)
            //        {
            //            var szName = (string)Marshal.PtrToStringAnsi(Marshal.ReadIntPtr(intPtrNameArray, m));
            //            if (string.IsNullOrEmpty(szName))
            //            {
            //                m += Global.Instance.PointerSize;
            //                if (m >= totalLength)
            //                    break;

            //                szName = (string)Marshal.PtrToStringAnsi(Marshal.ReadIntPtr(intPtrNameArray, m));
            //                var szChar = szName.ToUpper()[0];  //save protocol to indivitual entry per starting char
            //                if (bStartWrite == false)
            //                {
            //                    if (szChar != '1') //skip everything before 1xxx
            //                        continue;
            //                    bStartWrite = true;
            //                }
            //                if (currentChar != szChar)
            //                {
            //                    currentChar = szChar;
            //                    if (writer != null)
            //                    {
            //                        writer.Flush();
            //                        writer.Close();
            //                    }
            //                    Debug.Assert(charListHandled.Contains(szChar) == false);
            //                    charListHandled.Add(szChar);

            //                    writer = new StreamWriter(archive.CreateEntry(szChar.ToString()).Open());
            //                }
            //                writer.WriteLine();//write empty line to indicate a new protocol
            //            }
            //            if (bStartWrite)
            //                writer.WriteLine(szName);
            //        }
            //        if (writer != null)
            //        {
            //            writer.Flush();
            //            writer.Close();
            //        }
            //        //using (var writer = new StreamWriter(archive.CreateEntry("wpcap").Open()))
            //        //{
            //        //    for (int m = 0; m < arrayLength * tsharkHelper.PointerSize; m += tsharkHelper.PointerSize)
            //        //        writer.WriteLine((string)Marshal.PtrToStringAnsi(Marshal.ReadIntPtr(intPtrNameArray, m)));
            //        //    writer.Flush();
            //        //    writer.Close();
            //        //}
            //    }

            //}
            //finally
            //{
            //    if (intPtrNameArray != null)
            //        Common.Wireshark.tsharkWrapper.wz_Free_GetProtocolFieldNames(intPtrNameArray);
            //}
        }
        static bool IsLayer3(string szName)
        {
            switch (szName.ToUpper())
            {
                case "RRC":
                case "RRLP":
                case "HNBAP":
                case "LPP":
                case "M2AP":
                case "M3AP":
                case "NBAP":
                case "RANAP":
                case "RNSAP":
                case "RUA":
                case "S1AP":
                case "SABP":
                case "SNMP":
                case "X2AP":
                    return true;
            }
            return false;
        }
    }
}
