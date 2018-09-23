using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.IO;
using System.Collections;

namespace Sniffer_0._1
{
    public partial class Sniffer : Form
    {
        public Sniffer()
        {
            InitializeComponent();
        }

        private void Sniffer_Load(object sender, EventArgs e)
        {

        }

        private void button1_Click(object sender, EventArgs e)
        {
            StreamReader objReader = new StreamReader("trama.txt");
            string trama = "", direccionDestino="", direccionOrigen="", tipo="",version="", tipoServicio="",longitudTotal="", identificacion="", desplazamiento="", tiempovida="";
            string temp_o = "", temp_d = "", protocolo = "", check = "", ip_o = "", ip_d = "";
            int bytes=0;


            trama = objReader.ReadLine();
            direccionDestino = trama.Substring(0, 12);//6 Bytes
            direccionOrigen = trama.Substring(12, 12);//6 Bytes

            trama = objReader.ReadLine();
            tipo = trama.Substring(0, 4);//2 Bytes

            bytes = 2;
            for(int i = 0; i < 5; i++)
            {
                direccionDestino = direccionDestino.Insert(bytes, ":");
                direccionOrigen = direccionOrigen.Insert(bytes, ":");
                bytes += 3;
            }
            
            label1.Text = direccionOrigen.ToUpper();
            label2.Text = direccionDestino.ToUpper();

            switch (tipo)
            {
                case "0800":
                    version = trama.Substring(4, 2);//1 Bytes
                    tipoServicio = trama.Substring(6, 2);//1 Bytes
                    longitudTotal = trama.Substring(8, 4);//2 Bytes
                    identificacion = trama.Substring(12, 4);//2 Bytes
                    desplazamiento = trama.Substring(16, 4);//2 Bytes
                    tiempovida = trama.Substring(20, 2);//1 Bytes
                    protocolo = trama.Substring(22, 2);//1 Bytes

                    trama = objReader.ReadLine();
                    check = trama.Substring(0, 4);//2 Bytes
                    temp_o = trama.Substring(4, 8);//4 Bytes
                    temp_d = trama.Substring(12, 8);//4 Bytes

                    bytes = 0;
                    for (int i = 0; i < 4; i++)
                    {
                        ip_o += Convert.ToString(Convert.ToInt64(temp_o.Substring(bytes, 2), 16), 10);
                        ip_o = ip_o.Insert(ip_o.Length, ".");
                        ip_d += Convert.ToString(Convert.ToInt64(temp_d.Substring(bytes, 2), 16), 10);
                        ip_d = ip_d.Insert(ip_d.Length, ".");
                        bytes += 2;
                    }

                    groupBox2.Text = "Tipo: " + tipo + " (IP)";
                    label3.Text = version;
                    label4.Text = tipoServicio;
                    label5.Text = Convert.ToInt64(longitudTotal,16).ToString();
                    label6.Text = identificacion;
                    label7.Text = desplazamiento;
                    label8.Text = tiempovida;
                    label9.Text = protocolo;
                    label10.Text = check;
                    label11.Text = ip_d;
                    label12.Text = ip_o;
                    groupBox8.Text += " (TCP)";
                    objReader.Close();
                    break;

                case "0806":
                    MessageBox.Show("ARP");
                    break;
            }
        }
    }
} 
