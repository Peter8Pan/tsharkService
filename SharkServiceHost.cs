using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.ServiceProcess;
using System.ServiceModel;
using System.ServiceModel.Description;
using System.Management;
using System.Diagnostics;
using System.Reflection;
using System.Diagnostics;

namespace tsharkService
{
    public class SharkServiceHost
    {
        const string ServiceName = "SharkService";
        const int ServicePort = 8676;
        protected ServiceHost _serviceHost;
        protected NetTcpBinding _netTcpBinding;

        public SharkServiceHost()
        {
            this._netTcpBinding = SharkServiceHost.GetDefaultNetTcpBinding(TransferMode.Streamed);
            this._serviceHost = new ServiceHost(typeof(SharkService));
            this._serviceHost.AddServiceEndpoint(typeof(InterfaceSharkService), this._netTcpBinding, 
                new Uri($"net.tcp://127.0.0.1:{ServicePort}/{ServiceName}/"));
        }    
        public bool StartService()
        {
            var folder = Assembly.GetExecutingAssembly().Location;
            try
            {
                tsharkWrapper.RegisterWireshark(folder);
                // Enable exeption details
                var sdb = this._serviceHost.Description.Behaviors.Find<ServiceDebugBehavior>();
                sdb.IncludeExceptionDetailInFaults = true;

                this._serviceHost.Open();
                return true;
            }
            catch (Exception ex)
            {
                //Debugger.Launch();
                EventLog.WriteEntry("WireshackWcf", folder + "\n" + ex.Message + "\n" + ex.StackTrace, EventLogEntryType.Error);
            }

            return false;
        }
        public void StopService()
        {
            if (this._serviceHost == null)
                return;

            try
            {
                tsharkWrapper.UnRegisterWireshark();
                this._serviceHost.Close();
            }
            catch (Exception ex)
            {
                
            }
        }

        public bool IsServiceRunning()
        {
            if (this._serviceHost == null)
                return false;
            return this._serviceHost.State == CommunicationState.Opened;
        }
        public static NetTcpBinding GetDefaultNetTcpBinding(TransferMode transferMode = TransferMode.Buffered)
        {
            var binding = new NetTcpBinding(SecurityMode.None)
            {
                MaxConnections = 100,
                MaxBufferPoolSize = 64 * 1024 * 1024,

                MaxBufferSize = 64 * 1024 * 1024,
                MaxReceivedMessageSize = 64 * 1024 * 1024,
                TransferMode = transferMode,
                SendTimeout = TimeSpan.FromMinutes(30),
                ReceiveTimeout = TimeSpan.FromMinutes(30),
                CloseTimeout = TimeSpan.FromSeconds(10),
                OpenTimeout = TimeSpan.FromSeconds(10),
            };
            binding.ReaderQuotas.MaxDepth = 32;
            binding.ReaderQuotas.MaxStringContentLength =
            binding.ReaderQuotas.MaxArrayLength =
            binding.ReaderQuotas.MaxBytesPerRead = 2 * 1024 * 1024;
            binding.ReaderQuotas.MaxNameTableCharCount = 16 * 1024;

            binding.ReliableSession.Ordered = true;
            binding.ReliableSession.InactivityTimeout = TimeSpan.FromMinutes(30);
            binding.ReliableSession.Enabled = false;
            return binding;
        }

    }
}
