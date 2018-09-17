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
            string binario = "", direccionDestino="", direccionOrigen="", tipo="",version="", tipoServicio="",longitudTotal="", identificacion="", desplazamiento="", tiempovida="";
            int nibble=46, bits=0;
            binario = objReader.ReadLine();
            objReader.Close();
        
            for(int i = 0; i < nibble; i++)
            {
                if (bits >= 0 && bits <= 47)//48 bits
                    direccionDestino += Convert.ToString(Convert.ToInt64(binario.Substring(bits, 4), 2), 16);
                else if (bits >= 48 && bits <= 95 )//48 bits
                    direccionOrigen += Convert.ToString(Convert.ToInt64(binario.Substring(bits, 4), 2), 16);
                else if (bits >= 96 && bits <= 111)//16 bits
                    tipo += Convert.ToString(Convert.ToInt64(binario.Substring(bits, 4), 2), 16);
                else if (bits >= 112 && bits <= 119)//8 bits
                    version += Convert.ToString(Convert.ToInt64(binario.Substring(bits, 4), 2), 16);
                else if (bits >= 120 && bits <= 127)//8 bits
                    tipoServicio += Convert.ToString(Convert.ToInt64(binario.Substring(bits, 4), 2), 16);
                else if (bits >= 128 && bits <= 143)//16 bits
                    longitudTotal += Convert.ToString(Convert.ToInt64(binario.Substring(bits, 4), 2), 16);
                else if (bits >= 144 && bits <= 159)//16 bits
                    identificacion += Convert.ToString(Convert.ToInt64(binario.Substring(bits, 4), 2), 16);
                else if (bits >= 160 && bits <= 175)//16 bits
                    desplazamiento += Convert.ToString(Convert.ToInt64(binario.Substring(bits, 4), 2), 16);
                else if (bits >= 176 && bits <= 183)//8 bits
                    tiempovida += Convert.ToString(Convert.ToInt64(binario.Substring(bits, 4), 2), 16);

                bits += 4;
            }

            //Comentario mas grande

            bits = 2;
            for(int i = 0; i < 5; i++)
            {
                direccionDestino = direccionDestino.Insert(bits, ":");
                direccionOrigen = direccionOrigen.Insert(bits, ":");
                bits += 3;
            }
           

            label1.Text = direccionOrigen.ToUpper();
            label2.Text = direccionDestino.ToUpper();
            groupBox2.Text = "Tipo: " + tipo;
            label3.Text = version;
            label4.Text = tipoServicio;
            label5.Text = longitudTotal;
            label6.Text = identificacion;
            label7.Text = desplazamiento;
            label8.Text = tiempovida;

            switch (tipo)
            {
                case "0800":
                    groupBox2.Text += " (IP)";
                    MessageBox.Show("IP");
                    
                break;

                case "0806":
                    MessageBox.Show("ARP");
                break;
            }
        }
    }
} 
