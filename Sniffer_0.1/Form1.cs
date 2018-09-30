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
            timer1.Start();
        }

        private void button1_Click(object sender, EventArgs e)
        {
            StreamReader objReader = new StreamReader("trama.txt");//abrir archivo
            string trama = "", direccionDestino="", direccionOrigen="", tipo="",version="", tipoServicio="",longitudTotal="", identificacion="", desplazamiento="", tiempovida="";
            string temp_o = "", temp_d = "", protocolo = "", check = "", ip_o = "", ip_d = "";
            int bytes=0;


            trama = objReader.ReadLine();//linea 1
            direccionDestino = trama.Substring(0, 12);//6 Bytes
            direccionOrigen = trama.Substring(12, 12);//6 Bytes

            trama = objReader.ReadLine();//linea 2
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

                    trama = objReader.ReadLine();//linea 3
                    check = trama.Substring(0, 4);//2 Bytes
                    temp_o = trama.Substring(4, 8);//4 Bytes
                    temp_d = trama.Substring(12, 8);//4 Bytes

                    bytes = 0;
                    for (int i = 0; i < 4; i++)
                    {
                        ip_o += Convert.ToString(Convert.ToInt64(temp_o.Substring(bytes, 2), 16), 10);
                        ip_d += Convert.ToString(Convert.ToInt64(temp_d.Substring(bytes, 2), 16), 10);
                        if (i != 3){
                            ip_o = ip_o.Insert(ip_o.Length, ".");
                            ip_d = ip_d.Insert(ip_d.Length, ".");
                        }
                        bytes += 2;
                    }

                    groupBox2.Text = "Tipo:  " + tipo + "  (IP)";
                    label3.Text = "Version: "+version.Substring(0,1)+" (grupos)";
                    label23.Text = "Longitud: "+version.Substring(1, 1)+" bytes";
                    label4.Text = tipoServicio;
                    
                    //string tipoServicioBites = Convert.ToString(Convert.ToInt64(tipoServicio,16),2);
                    //string precedencia = tipoServicioBites.Substring(0, 3);
                    //string TOS = tipoServicioBites.Substring(3, 4);
                    //string MBZ = tipoServicioBites.Substring(7, 1);

                    switch (tipoServicio)
                    {
                        case "00":
                            label18.Text = "Rutina";
                            label19.Text = "Servicio normal";
                        break;

                        case "20":
                            label18.Text = "Prioridad";
                            label19.Text = "Servicio normal";
                            break;

                        case "40":
                            label18.Text = "Inmediato";
                            label19.Text = "Servicio normal";
                            break;

                        case "60":
                            label18.Text = "Flash";
                            label19.Text = "Servicio normal";
                            break;

                        case "80":
                            label18.Text = "Flash Override";
                            label19.Text = "Servicio normal";
                            break;
                    }
                    
                    label5.Text = Convert.ToInt64(longitudTotal,16).ToString() + " bytes";
                    label6.Text = identificacion;

                    
                    label7.Text = desplazamiento;

                    switch (desplazamiento)
                    {
                        case "2000":
                            label20.Text = "Mas fragmentos";
                            label21.Text = "No es el ultimo paquete";
                            break;

                        case "4000":
                            label20.Text = "No fragmentado";
                            label21.Text = "Ultimo paquete";
                            break;
                        case "8000":
                            label20.Text = "Reservado";
                            label21.Text = "Ultimo paquete";
                            break;
                    }
                    label8.Text = Convert.ToInt64(tiempovida,16).ToString() + " segundos";
                    label10.Text = check;
                    label9.Text = "Calculo :";
                    label11.Text = ip_d;
                    label12.Text = ip_o;
                    switch (protocolo)
                    {
                        case "06":
                            string puertoOrigen = "", puertoDestino = "", numeroSecuencia = "", numeroConfirmacion = "", longCabeceraTCP = "", banderasTCP = "", tamañoVentanaTCP = "", checksumTCP = "", punteroUrgente = "", opciones = "";                     
                            groupBox12.Text = "Protocolo:  " + protocolo + "  (TCP)";

                            puertoOrigen = trama.Substring(20, 4);//2 Bytes

                            trama = objReader.ReadLine();//linea 4
                            puertoDestino = trama.Substring(0, 4);//2 Bytes
                            numeroSecuencia = trama.Substring(4, 8);//4 Bytes
                            numeroConfirmacion = trama.Substring(12, 8);//4 bytes
                            longCabeceraTCP = trama.Substring(20, 2);//1 byte
                            banderasTCP = trama.Substring(22, 2);//1 byte

                            trama = objReader.ReadLine();//linea 5
                            tamañoVentanaTCP = trama.Substring(0, 4);//2 bytes
                            checksumTCP = trama.Substring(4, 4);//2 bytes
                            punteroUrgente = trama.Substring(8, 4);//2 bytes
                            opciones = trama.Substring(12, 6);//3 bytes














                            label13.Text = Convert.ToInt64(puertoOrigen, 16).ToString();
                            label14.Text = Convert.ToInt64(puertoDestino, 16).ToString();
                            label15.Text = numeroSecuencia;
                            label24.Text = numeroConfirmacion;
                            label25.Text = Convert.ToInt64(longCabeceraTCP.Substring(0,1), 16).ToString() + " bytes";
                            label26.Text = banderasTCP;


                            break;
                    }
                    objReader.Close();//cerrar archivo
                    break;

                case "0806":
                    MessageBox.Show("ARP");
                    break;
            }
        }

        private void timer1_Tick(object sender, EventArgs e)
        {
            label16.Text = "Fecha: "+ DateTime.Now.ToString("dd/MM/yyyy");
            label17.Text = "Hora: "+ DateTime.Now.ToString("hh:mm:ss");
        }
    }
} 
