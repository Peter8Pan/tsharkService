using System;
using System.IO;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Linq;
using System.ServiceProcess;
using System.Text;
using System.Threading.Tasks;
using System.Threading;
using System.Reflection;
using System.Diagnostics;

namespace tsharkService
{
    public partial class WiresharkWcf : ServiceBase
    {
        SharkServiceHost _sharkServiceHost = null;
        public WiresharkWcf()
        {
            InitializeComponent();
        }
        protected override void OnStart(string[] args)
        {
            Thread.CurrentThread.CurrentUICulture = new System.Globalization.CultureInfo("en-us");
            AppDomain.CurrentDomain.UnhandledException += CurrentDomain_UnhandledException;

#if DEBUG
            System.Diagnostics.Debugger.Launch();
#endif
            System.Threading.Thread.CurrentThread.Name = "Starting Host Service";
            try
            {
                this._sharkServiceHost = new SharkServiceHost();
                if (this._sharkServiceHost.StartService() == false)
                    ThreadPool.QueueUserWorkItem(new WaitCallback(delegate (object o) { this.Stop(); }), null);
            }
            catch (Exception ex)
            {
                EventLog.WriteEntry("WireshackWcf", ex.Message + "\n" + ex.StackTrace, EventLogEntryType.Error);
            }
        }
        private void CurrentDomain_UnhandledException(object sender, UnhandledExceptionEventArgs e)
        {
            var ex = e.ExceptionObject as Exception;
            EventLog.WriteEntry("WireshackWcf", ex.Message+"\n"+ex.StackTrace, EventLogEntryType.Error);
        }
        protected override void OnStop()
        {
            this._sharkServiceHost?.StopService();
        }
    }
}
