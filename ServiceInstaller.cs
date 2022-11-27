using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Configuration.Install;
using System.Linq;
using System.Threading.Tasks;
using System.ServiceProcess;

namespace tsharkService
{
    [RunInstaller(true)]
    public partial class ServiceInstaller : System.Configuration.Install.Installer
    {
        private System.ServiceProcess.ServiceInstaller serviceInstaller1;
        private System.ServiceProcess.ServiceProcessInstaller processInstaller;
        public ServiceInstaller()
        {
            InitializeComponent();

            // Instantiate installers for process and services.
            processInstaller = new System.ServiceProcess.ServiceProcessInstaller();
            serviceInstaller1 = new System.ServiceProcess.ServiceInstaller();

            // The services run under the system account.
            processInstaller.Account = ServiceAccount.LocalService;
            processInstaller.Username = null;
            processInstaller.Password = null;

            // The services are started manually.
            serviceInstaller1.StartType = ServiceStartMode.Automatic;

            // ServiceName must equal those on ServiceBase derived classes.
            serviceInstaller1.Description = "Wireshark WCF Service";
            serviceInstaller1.DisplayName = serviceInstaller1.ServiceName = "WiresharkWcf";

            // Add installers to collection. Order is not important.
            Installers.Add(serviceInstaller1);
            Installers.Add(processInstaller);
        }
    }
}
