using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Net;

namespace Sniffer_0._1
{
    public partial class Inicio : Form
    {
        public Inicio()
        {
            InitializeComponent();
        }

        private void btnStart_Click(object sender, EventArgs e)
        {

        }

        private void Inicio_Load(object sender, EventArgs e)
        {
            InitBufferSizeChooserCtrl();
            InitIPChooserCtrl();
        }

        private void InitIPChooserCtrl()
        {
            string hostName = Dns.GetHostName();
            IPAddress[] IPs = Dns.GetHostAddresses(hostName);

            foreach (IPAddress ip in IPs)
            {
                _view.AddIPItem(ip.ToString());
            }
        }

        private void InitBufferSizeChooserCtrl()
        {
            for (int i = 100; i < 1000; i += 100)
                _view.AddBufferSizeItem(i.ToString());

            for (int j = 1000; j < 100000; j += 1000)
                _view.AddBufferSizeItem(j.ToString());

            _view.SelectedBufferSize = 1000;
        }
    }
}
