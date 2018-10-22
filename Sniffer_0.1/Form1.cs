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
            //yeah
        }

        public string RellenoOchoBits(string hexa)
        {
            while (hexa.Length < 8)
            {
                hexa= String.Concat("0", hexa);
            } 

            return hexa;
        }

        public string Relleno16Bits(string hexa)
        {
            while (hexa.Length < 16) 
            {
                hexa = String.Concat("0", hexa);
            }

            return hexa;
        }

        public string Complemento(string palabra)
        {
            string comp="";

            for (int i = 0; i < 16; i++)
            {
                if (palabra[i].Equals('1'))
                {
                    comp += "0";
                }
                else
                {
                    comp += "1";
                }
            }

            return comp;
        }

        public string sumar(string palabra1, string palabra2)
        {
            string sum = "";
            bool carry = false;

            for (int i = 15; i >= 0; i--)
            {
                if (palabra1[i].Equals('1') && palabra2[i].Equals('1'))
                {
                    if (carry)
                    {
                        sum = "1" + sum;
                    }
                    else
                    {
                        sum = "0" + sum;
                    }
                    carry = true;
                }
                else if (palabra1[i].Equals('0') && palabra2[i].Equals('0'))
                {
                    if (carry)
                    {
                        sum = "1" + sum;
                    }
                    else
                    {
                        sum = "0" + sum;
                    }
                    carry = false;
                }
                else
                {
                    if (carry)
                    {
                        sum = "0" + sum;
                        carry = true;
                    }
                    else
                    {
                        sum = "1" + sum;
                        carry = false;
                    }
                }
            }
            if (carry)
            {
                sum =sumar(sum, "0000000000000001");
            }

            return sum;
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

                    tipoServicio = Convert.ToString(Convert.ToInt64(tipoServicio,16),2);//Convertir a binario
                    tipoServicio= RellenoOchoBits(tipoServicio);//Rellenar ceros en binario
                    string ts = tipoServicio;//Para checksum
                    label4.Text = tipoServicio.Substring(0,3) + " " + tipoServicio.Substring(3, 4) + " " + tipoServicio.Substring(7, 1);//Separa la cadena por espacios, dependiendo de las banderas
                    string precedencia = tipoServicio.Substring(0, 3);
                    string TOS = tipoServicio.Substring(3, 4);
                    string MBZ = tipoServicio.Substring(7, 1);//No agregado a Form

                    switch (precedencia)
                    {
                        case "000":
                            label18.Text = "Rutina";
                            break;
                        case "001":
                            label18.Text = "Prioridad";
                            break;
                        case "010":
                            label18.Text = "Inmediato";
                            break;
                        case "011":
                            label18.Text = "Flash";
                            break;
                        case "100":
                            label18.Text = "Flash Override";
                            break;
                        case "101":
                            label18.Text = "Critico";
                            break;
                        case "110":
                            label18.Text = "Internetwork control";
                            break;
                        case "111":
                            label18.Text = "Network control";
                            break;
                    }

                    switch (TOS)
                    {
                        case "1000":
                            label19.Text = "Minimizar retardo";
                            break;
                        case "0100":
                            label19.Text = "Maximizar la densidad de flujo";
                            break;
                        case "0010":
                            label19.Text = "Maximizar la fiabilidad";
                            break;
                        case "0001":
                            label19.Text = "Minimizar el coste monetario";
                            break;
                        case "0000":
                            label19.Text = "Servicio normal";
                            break;
                    }
                    
                    label5.Text = Convert.ToInt64(longitudTotal,16).ToString() + " bytes";
                    label6.Text = identificacion;


                    
                    desplazamiento = Convert.ToString(Convert.ToInt64(desplazamiento, 16), 2);//Convertir a binario
                    desplazamiento = Relleno16Bits(desplazamiento);//Rellenar ceros
                    string ds = desplazamiento;
                    string banderasDesplazamiento = desplazamiento.Substring(0, 3);
                    string desp = desplazamiento.Substring(3, 13);
                    label7.Text = desp;
                    switch (banderasDesplazamiento)
                    {
                        case "001":
                            label20.Text = "Mas fragmentos";
                            label21.Text = "No es el ultimo paquete";
                            break;

                        case "010":
                            label20.Text = "No fragmentado";
                            label21.Text = "Ultimo paquete";
                            break;
                        case "101":
                            label20.Text = "Reservado";
                            label21.Text = "Ultimo paquete";
                            break;
                    }
                    label8.Text = Convert.ToInt64(tiempovida,16).ToString() + " segundos";
                    label10.Text = check;

                    // Convertir desde antes
                    string primeraPalabra = Convert.ToString(Convert.ToInt64(version, 16), 2) + ts;
                    primeraPalabra = Relleno16Bits(primeraPalabra);
                    string segundaPalabra = Convert.ToString(Convert.ToInt64(longitudTotal, 16), 2);
                    segundaPalabra = Relleno16Bits(segundaPalabra);
                    string terceraPalabra = Convert.ToString(Convert.ToInt64(identificacion, 16), 2);
                    terceraPalabra = Relleno16Bits(terceraPalabra);
                    string cuartaPalabra = ds;
                    string quintaPalabra = Convert.ToString(Convert.ToInt64(protocolo, 16), 2);
                    quintaPalabra = RellenoOchoBits(quintaPalabra);
                    quintaPalabra = Convert.ToString(Convert.ToInt64(tiempovida, 16), 2) + quintaPalabra;
                    quintaPalabra = Relleno16Bits(quintaPalabra);
                    string sextaPalabra = "0000000000000000";
                    string septimaPalabra = Convert.ToString(Convert.ToInt64(temp_o.Substring(0, 4), 16), 2);
                    septimaPalabra = Relleno16Bits(septimaPalabra);
                    string octavaPalabra = Convert.ToString(Convert.ToInt64(temp_o.Substring(4, 4), 16), 2);
                    octavaPalabra = Relleno16Bits(octavaPalabra);
                    string novenaPalabra = Convert.ToString(Convert.ToInt64(temp_d.Substring(0, 4), 16), 2);
                    novenaPalabra = Relleno16Bits(novenaPalabra);
                    string decimapalabra = Convert.ToString(Convert.ToInt64(temp_d.Substring(4, 4), 16), 2);
                    decimapalabra = Relleno16Bits(decimapalabra);
                    

                    string suma1,suma2,sumat;

                    /*MessageBox.Show(Convert.ToString(Convert.ToInt64(primeraPalabra, 2), 16));
                    MessageBox.Show(Convert.ToString(Convert.ToInt64(segundaPalabra, 2), 16));
                    MessageBox.Show(Convert.ToString(Convert.ToInt64(terceraPalabra, 2), 16));
                    MessageBox.Show(Convert.ToString(Convert.ToInt64(cuartaPalabra, 2), 16));
                    MessageBox.Show(Convert.ToString(Convert.ToInt64(quintaPalabra, 2), 16));*/
                    suma1 = sumar(primeraPalabra, segundaPalabra);
                    suma1 = sumar(suma1, terceraPalabra);
                    suma1 = sumar(suma1, cuartaPalabra);
                    suma1 = sumar(suma1, quintaPalabra);

                    /*MessageBox.Show(Convert.ToString(Convert.ToInt64(sextaPalabra, 2), 16));
                    MessageBox.Show(Convert.ToString(Convert.ToInt64(septimaPalabra, 2), 16));
                    MessageBox.Show(Convert.ToString(Convert.ToInt64(octavaPalabra, 2), 16));
                    MessageBox.Show(Convert.ToString(Convert.ToInt64(novenaPalabra, 2), 16));
                    MessageBox.Show(Convert.ToString(Convert.ToInt64(decimapalabra, 2), 16));*/
                    suma2 = sumar(sextaPalabra, septimaPalabra);
                    suma2 = sumar(suma2, octavaPalabra);
                    suma2 = sumar(suma2, novenaPalabra);
                    suma2 = sumar(suma2, decimapalabra);

                    sumat = sumar(suma1, suma2);
                    sumat = Complemento(sumat);
                    


                    label9.Text = "Calculo :";
                    label22.Text = Convert.ToString(Convert.ToInt64(sumat, 2), 16);

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

                            banderasTCP= Convert.ToString(Convert.ToInt64(banderasTCP, 16), 2);
                            banderasTCP = RellenoOchoBits(banderasTCP);
                            label13.Text = Convert.ToInt64(puertoOrigen, 16).ToString();
                            label14.Text = Convert.ToInt64(puertoDestino, 16).ToString();
                            label15.Text = Convert.ToInt64(numeroSecuencia, 16).ToString();
                            label24.Text = Convert.ToInt64(numeroConfirmacion, 16).ToString();
                            label25.Text = Convert.ToInt64(longCabeceraTCP.Substring(0,1), 16).ToString() + " bytes";
                            //label26.Text = banderasTCP;
                            if (banderasTCP.Substring(2, 1).ToString() == "1")
                            {
                                label26.Text = "URG = 1";
                            }
                            if (banderasTCP.Substring(3, 1).ToString() == "1")
                            {
                                label30.Text = "ACK = 1";
                            }
                            if (banderasTCP.Substring(4, 1).ToString() == "1")
                            {
                                label31.Text = "PSH = 1";
                            }
                            if (banderasTCP.Substring(5, 1).ToString() == "1")
                            {
                                label34.Text = "RST = 1";
                            }
                            if (banderasTCP.Substring(6, 1).ToString() == "1")
                            {
                                label33.Text = "SYN = 1";
                            }
                            if (banderasTCP.Substring(7, 1).ToString() == "1")
                            {
                                label32.Text = "FIN = 1";
                            }
                            label27.Text = Convert.ToInt64(tamañoVentanaTCP, 16).ToString() + " bytes";
                            label28.Text = checksumTCP;
                            label29.Text = punteroUrgente;


                            string datos = trama.Substring(18, 6);

                            trama = objReader.ReadLine();//linea 6
                            datos += trama;
                            trama = objReader.ReadLine();//linea 7
                            datos += trama;
                            trama = objReader.ReadLine();//linea 8
                            datos += trama;
                            trama = objReader.ReadLine();//linea 9
                            datos += trama;
                            trama = objReader.ReadLine();//linea 10
                            datos += trama;

                            string sumasc, sumatcp, sumad, sumaf;

                            int segmento = datos.Length / 2;
                            segmento += 28;

                            string palabra1tcp = Convert.ToString(Convert.ToInt64(temp_o.Substring(0, 4), 16), 2);
                            palabra1tcp = Relleno16Bits(palabra1tcp);
                            string palabra2tcp = Convert.ToString(Convert.ToInt64(temp_o.Substring(4, 4), 16), 2);
                            palabra2tcp = Relleno16Bits(palabra2tcp);
                            string palabra3tcp = Convert.ToString(Convert.ToInt64(temp_d.Substring(0, 4), 16), 2);
                            palabra3tcp = Relleno16Bits(palabra3tcp);
                            string palabra4tcp = Convert.ToString(Convert.ToInt64(temp_d.Substring(4, 4), 16), 2);
                            palabra4tcp = Relleno16Bits(palabra4tcp);
                            string palabra5tcp = Convert.ToString(Convert.ToInt64(protocolo, 16), 2);
                            palabra5tcp = Relleno16Bits(palabra5tcp);
                            string palabra6tcp = Convert.ToString(segmento, 2);
                            palabra6tcp = Relleno16Bits(palabra6tcp);

                            sumasc = sumar(palabra1tcp, palabra2tcp);
                            sumasc = sumar(sumasc, palabra3tcp);
                            sumasc = sumar(sumasc, palabra4tcp);
                            sumasc = sumar(sumasc, palabra5tcp);
                            sumasc = sumar(sumasc, palabra6tcp);

                            //MessageBox.Show(Convert.ToString(Convert.ToInt64(sumasc, 2), 16));


                            string palabra7tcp = Convert.ToString(Convert.ToInt64(puertoOrigen, 16), 2);
                            palabra7tcp = Relleno16Bits(palabra7tcp);
                            string palabra8tcp = Convert.ToString(Convert.ToInt64(puertoDestino, 16), 2);
                            palabra8tcp = Relleno16Bits(palabra8tcp);
                            string palabra9tcp = Convert.ToString(Convert.ToInt64(numeroSecuencia.Substring(0, 4), 16), 2);
                            palabra9tcp = Relleno16Bits(palabra9tcp);
                            string palabra10tcp = Convert.ToString(Convert.ToInt64(numeroSecuencia.Substring(4, 4), 16), 2);
                            palabra10tcp = Relleno16Bits(palabra10tcp);
                            string palabra11tcp = Convert.ToString(Convert.ToInt64(numeroConfirmacion.Substring(0, 4), 16), 2);
                            palabra11tcp = Relleno16Bits(palabra11tcp);
                            string palabra12tcp = Convert.ToString(Convert.ToInt64(numeroConfirmacion.Substring(4, 4), 16), 2);
                            palabra12tcp = Relleno16Bits(palabra12tcp);
                            string palabra13tcp = banderasTCP;
                            palabra13tcp = RellenoOchoBits(palabra13tcp);
                            palabra13tcp = Convert.ToString(Convert.ToInt64(longCabeceraTCP, 16), 2) + palabra13tcp;
                            palabra13tcp = Relleno16Bits(palabra13tcp);
                            string palabra14tcp = Convert.ToString(Convert.ToInt64(tamañoVentanaTCP, 16), 2);
                            palabra14tcp = Relleno16Bits(palabra14tcp);
                            string palabra15tcp = "0000000000000000";
                            string palabra16tcp = Convert.ToString(Convert.ToInt64(punteroUrgente, 16), 2);
                            palabra16tcp = Relleno16Bits(palabra16tcp);
                            string palabra17tcp = Convert.ToString(Convert.ToInt64(opciones.Substring(0, 4), 16), 2);
                            palabra17tcp = Relleno16Bits(palabra17tcp);
                            string palabra18tcp = "00000000";
                            palabra18tcp = Convert.ToString(Convert.ToInt64(opciones.Substring(4, 2), 16), 2) + palabra18tcp;
                            palabra18tcp = Relleno16Bits(palabra18tcp);

                            sumatcp = sumar(palabra7tcp, palabra8tcp);
                            sumatcp = sumar(sumatcp, palabra9tcp);
                            sumatcp = sumar(sumatcp, palabra10tcp);
                            sumatcp = sumar(sumatcp, palabra11tcp);
                            sumatcp = sumar(sumatcp, palabra12tcp);
                            sumatcp = sumar(sumatcp, palabra13tcp);
                            sumatcp = sumar(sumatcp, palabra14tcp);
                            sumatcp = sumar(sumatcp, palabra15tcp);
                            sumatcp = sumar(sumatcp, palabra16tcp);
                            sumatcp = sumar(sumatcp, palabra17tcp);
                            sumatcp = sumar(sumatcp, palabra18tcp);

                            //MessageBox.Show(Convert.ToString(Convert.ToInt64(sumatcp, 2), 16));


                            sumad = sumar(Relleno16Bits(Convert.ToString(Convert.ToInt64(datos.Substring(0, 4), 16), 2)), Relleno16Bits(Convert.ToString(Convert.ToInt64(datos.Substring(4, 4), 16), 2)));
                            int bits = 8;
                            int tam = datos.Length / 2;
                            if (tam % 2 == 1)
                            {
                                tam += 1;
                                datos += "00";
                            }
                            for(int i=0; i<(tam / 2)-2; i++)
                            {
                                sumad = sumar(sumad, Relleno16Bits(Convert.ToString(Convert.ToInt64(datos.Substring(bits, 4), 16), 2)));
                                bits += 4;
                            }

                            sumaf = sumar(sumasc, sumatcp);
                            sumaf = sumar(sumaf, sumad);

                            //sumaf = Complemento(sumaf);

                            MessageBox.Show(Convert.ToString(Convert.ToInt64(sumaf, 2), 16));


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

        private void button2_Click(object sender, EventArgs e)
        {
            Application.Exit();
        }
    }
} 
