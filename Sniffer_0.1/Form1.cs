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
            string temp_o = "", temp_d = "", protocolo = "", check = "", ip_o = "", ip_d = "";
            int nibble=68, bits=0;
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
                else if (bits >= 184 && bits <= 191)//8 bits
                    protocolo += Convert.ToString(Convert.ToInt64(binario.Substring(bits, 4), 2), 16);
                else if (bits >= 192 && bits <= 207)//16 bits
                    check += Convert.ToString(Convert.ToInt64(binario.Substring(bits, 4), 2), 16);
                else if (bits >= 208 && bits <= 239)//16 bits
                    temp_o += Convert.ToString(Convert.ToInt64(binario.Substring(bits, 4), 2), 16);
                else if (bits >= 240 && bits <= 271)//16 bits
                    temp_d += Convert.ToString(Convert.ToInt64(binario.Substring(bits, 4), 2), 16);

                bits += 4;
            }

            //Comentario mas grande 
            //mi comentario

            bits = 2;
            for(int i = 0; i < 5; i++)
            {
                direccionDestino = direccionDestino.Insert(bits, ":");
                direccionOrigen = direccionOrigen.Insert(bits, ":");
                bits += 3;
            }

            bits = 0;
            for (int i = 0; i < 4; i++)
            {
                ip_o += Convert.ToString(Convert.ToInt64(temp_o.Substring(bits, 2), 16), 10);
                ip_o = ip_o.Insert(ip_o.Length, ".");
                ip_d += Convert.ToString(Convert.ToInt64(temp_d.Substring(bits, 2), 16), 10);
                ip_d = ip_d.Insert(ip_d.Length, ".");
                bits += 2;
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
            label9.Text = protocolo;
            label10.Text = check;
            label11.Text = ip_d;
            label12.Text = ip_o;

            switch (tipo)
            {
                case "0800":
                    groupBox2.Text += " (IP)";
                    
                break;

                case "0806":
                    MessageBox.Show("ARP");
                break;
            }
        }
    }
} 
