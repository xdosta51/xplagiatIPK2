/* include potrebnych knihoven */
/*system */
using System; 
using System.Net;
using System.Net.NetworkInformation;
/* libpcap pro csharp */
using SharpPcap;
using SharpPcap.LibPcap;
/* knihovna pro parse paketu */
using PacketDotNet;


namespace ipk2 {

    class Program {

        /*funkci na vypis zarizeni */
        
        static void vypis() {
            /* ziska seznam zarizeni */
            var devices = CaptureDeviceList.Instance;

            /*pokud jsme nenalezli zadne zarizeni */
            if (devices.Count < 1) {
                Console.WriteLine("Nenasly jsme zarizeni k odposlouchavani");
                return;
            }
            /*vypise seznam zarizeni */
            foreach (var dev in devices) {
                Console.WriteLine(dev.Name);
            }
                System.Environment.Exit(0);
        }

        static void Main(string[] args)
        {   /* promenne pro parse argumentu */
            int onlytcp = 0;
            int onlyudp = 0;
            int onlyipv6 = 0;
            int pocet_paketu = 1;
            string rozhrani = "";
            int portik = -1;
            int jeizadane = 0;
            /* pruchod pres argumenty */
            for (int index = 0; index < args.Length; index++) {
                string value = args[index];
                /* vypis pozadovaneho poctu paketu */
                if (string.Compare(value,"-n") == 0) {
                    try {
                        pocet_paketu = Int32.Parse(args[index+1]);
                        if (pocet_paketu <= 0) {
                            Console.WriteLine("Nespravny pocet paketu");
                            System.Environment.Exit(1);
                        }
                    }
                    catch {
                        pocet_paketu = 1;
                    }
                }
                /*byl zadan argument i pokud za i chyby vypise se seznam rozhrani */
                if (string.Compare(value,"-i") == 0) {
                    try {
                        rozhrani = args[index+1];
                    }
                    catch {
                        vypis();
                    }
                    jeizadane = 1;
                }
                /* pouze tcp pakety */
                if (string.Compare(value,"--tcp") == 0) {
                    onlytcp = 1;
                }
                /* pouze udp pakety */
                if (string.Compare(value,"--udp") == 0) {
                    onlyudp = 1;
                }
                /* byl zadan argument t chceme pouze tcp pakety */
                if (string.Compare(value,"-t") == 0) {
                    onlytcp = 1;
                }
                /* byl zadan argument u chceme pouze udp pakety */
                if (string.Compare(value,"-u") == 0) {
                    onlyudp = 1;
                }
                /* byl zadan argument -p provede se filtrovani podle portu */
                if (string.Compare(value,"-p") == 0) {
                    try {
                        portik = Int32.Parse(args[index+1]);
                        if (portik < 0 || portik > 65535)
                            {
                                Console.WriteLine("chybny port");
                                System.Environment.Exit(-1);
                            }
                    }
                    catch {
                        Console.WriteLine("Chyba pri zadavani cisla portu");
                        System.Environment.Exit(-1);
                    }
                }
                if (string.Compare(value,"-ipv6") == 0) {
                    onlyipv6 = 1;
                }
            }
            
            
            /* ziska seznam zarizeni */
            var devices = CaptureDeviceList.Instance;

            /*pokud jsme nenalezli zadne zarizeni */
            if (devices.Count < 1)
            {
                Console.WriteLine("Nenasly jsme zarizeni k odposlouchavani");
                return;
            }

            /* promenna pro pruchod cyklem a pro zvolene zarizeni */
            int zarizeni = -1;
            int i = 0;

            // projde pres vsechny zarizeni a najde pozadovane rozhrani
            foreach (var dev in devices)
            {
                if (string.Compare(dev.Name,rozhrani) == 0) {
                    zarizeni = i;
                }
                i++;
            }
            /*pokud jste nezadali i vypise seznam zarizeni */
            if (jeizadane == 0) {
                foreach (var dev in devices) {
                    Console.WriteLine(dev.Name);
                }
                System.Environment.Exit(0);
            }

            if (zarizeni == -1) {
                Console.WriteLine("Zarizeni k odposlouchavani neexistuje");
                System.Environment.Exit(-1);
            }

           /*priradi zarizeni zvolene zarizeni */
            var device = devices[zarizeni];
            
            // otevre zarizeni pro naslouchani
            /* prevzato z https://github.com/chmorgan/sharppcap/blob/master/Examples/Example4.BasicCapNoCallback/Example4.BasicCapNoCallback.cs */
            int readTimeoutMilliseconds = 1000;
            device.Open(DeviceMode.Promiscuous, readTimeoutMilliseconds);

            /* promenna pro paket */
            RawCapture packet;

            /*promenna pro vypis pozadovaneho poctu paketu */
            int paketky = 0;

            /*cyklem prochazime paketu po paketu ze zvoleneho zarizeni */
            while ((packet = device.GetNextPacket()) != null)
            {   

                try {
                    /*parsovani paketu */
                    var packet_parse = PacketDotNet.Packet.ParsePacket(packet.LinkLayerType, packet.Data);
                    var tcp = packet_parse.Extract<PacketDotNet.TcpPacket>();
                    var udp = packet_parse.Extract<PacketDotNet.UdpPacket>();
                    /*ziskani ipv4 packetu */
                    var ipv4pak = packet_parse.Extract<PacketDotNet.IPv4Packet>();
                    var ipv6pak = packet_parse.Extract<PacketDotNet.IPv6Packet>();          
                    
                     /* podporuje pouze tcp a udp pakety */
                    if (tcp == null && udp == null) {
                        
                        continue;
                    }

                    if (onlytcp != 1 || onlyudp != 1) {
                        /*kontrola jestli se jedna o tcp pokud jo kontrola podle portu nebo pokud je jenom udp */
                        if (tcp != null) {
                            
                            if (onlyudp == 1) {
                                if (onlytcp == 0)
                                    continue;
                            }
                            if (portik != -1) {
                                if (portik != tcp.SourcePort && portik != tcp.DestinationPort)
                                    continue;
                            }
                        }

                        /* kontrola jestli se jedna o udp a pokud jo filtrace podle portu nebo jestli je tcp only*/
                        if (udp != null) {
                            
                            if (onlytcp == 1) {
                                if (onlyudp == 0)
                                    continue;
                            }
                            if (portik != -1) {
                                if (portik != udp.SourcePort && portik != udp.DestinationPort)
                                    continue;
                            }
                        }
                    }/* chceme oba pakety aplikovani filtru na porty */
                    else {
                        if (tcp != null) {
                            
                            if (portik != -1) {
                                if (portik != tcp.SourcePort && portik != tcp.DestinationPort)
                                    continue;
                            }
                        }
                        if (udp != null) {
                            
                            if (portik != -1) {
                                if (portik != udp.SourcePort && portik != udp.DestinationPort)
                                    continue;
                            }
                        }
                    }
                    /* ziskani source a dest adresy */

                    string srcip = "";
                    string dstip = "";
                    /* ipv4 paket */
                    if (ipv4pak != null) {
                        if (onlyipv6 == 1)
                            continue;
                        srcip = ipv4pak.SourceAddress.ToString();
                        dstip = ipv4pak.DestinationAddress.ToString();
                    } /* ipv6 paket */
                    else {
                        if (ipv6pak == null) {
                            continue;
                        }
                        srcip = ipv6pak.SourceAddress.ToString();
                        dstip = ipv6pak.DestinationAddress.ToString();
                    }
                    
                    /*promenna pro ziskani casu z paketu */
                    var time = packet.Timeval.Date;
                    
                    /*formatovani casu + zdrojova ip adresa */
                    Console.Write("{0}:{1}:{2}",
                    time.Hour, time.Minute, time.Second);
                    Console.Write(".");
                    Console.Write(packet.Timeval.MicroSeconds);
                    Console.Write(" ");
                    Console.Write(srcip);
                    

                    

                    /*vypise bud tcp nebo udp sourceport */
                    if (tcp != null) {
                        Console.Write(" : ");
                        Console.Write(tcp.SourcePort);
                    }
                    if (udp != null) {
                        Console.Write(" : ");
                        Console.Write(udp.SourcePort);
                    }

                    /* vypis podle formatu */
                    Console.Write(" > ");
                    Console.Write(dstip);

                    /*pokud tcp neni null vypise se dest port */
                    if (tcp != null) {
                        Console.Write(" : ");
                        Console.Write(tcp.DestinationPort);
                    }

                    /* pokud ud neni null vypise se dest port */
                    if (udp != null) {
                        Console.Write(" : ");
                        Console.Write(udp.DestinationPort);
                    }


                    /*vypis dvou prazdnych radku */
                    Console.WriteLine();
                    Console.WriteLine();
                    
                    /*promenna pro posledni radek */
                    string konec = "";

                    /*rozkodovani paketu */
                    string result = System.Text.Encoding.UTF8.GetString(packet.Data);
                    /* mensi predelavka kodu */
                    result = "";
                    /* rozparsovani na byty a jednotlive chary */
                    foreach (byte bitik in packet.Data) {
                        char vOut = Convert.ToChar(bitik);
                        result = result + vOut;
                    }

                    /*promenna pro radek a byte value */
                    int byteValues = 0;
                    string radek = "";

                    /*pruchod celym paketem */
                    for( int index = 0; index < result.Length; index++) {
                        
                        /*kontrola jestli lze radek vypsat */
                        var isPrintable = ! Char.IsControl(result[index]);
                        int b = result[index] - 0;

                        /*spravne formatovani prvniho radku */
                        if (index == 0) {
                            Console.Write("0x0000:");
                            Console.Write(" ");
                        }

                        /*konvertovani znaku na hexa */
                        string hex = Convert.ToString(b, 16);

                        /*chyceni podretezce */
                        try {
                        hex = hex.Substring(hex.Length - 2);
                        }
                        catch {
                            hex = hex.Substring(hex.Length - 1);
                            hex = "0" + hex;
                        }

                        /*vypise se mezera */
                        Console.Write(" ");

                        /*znak lze vypsat ulozi se do radku */
                        if (b > 31 && b <127) {
                            radek = radek + result[index];
                        }

                        /*kontrola vypisovatelneho znaku */
                        else {
                            radek = radek + ".";
                        }

                        /*prvek hexa vypsani*/
                        Console.Write(hex);

                        /* vypis prvni mezery za 8 prvkem */
                        if (((index+1) % 8) == 0 && index != 0)  {
                                radek = radek + " ";
                        } 

                        /* vypsani radku v ascii + spravne formatovani */
                        if (index != 0 && index > 16) {
                            if (((index+1) % 16) == 0)  {
                                Console.Write("  ");
                                Console.Write(radek);
                                konec=radek;
                                radek = "";
                                Console.WriteLine();
                                byteValues = byteValues +16;
                                if (index+1 == result.Length) {
                                    konec = "";
                                    break;
                                }
                                Console.Write("0x");
                                Console.Write(byteValues.ToString("x4"));
                                Console.Write(":");
                                
                            } 

                            /*vypsani mezery po 8 prvku */
                            if (((index+1) % 8) == 0)  {
                                Console.Write(" ");
                            }

                        }
                        /* vypsani radku v ASCII + spravne formatovani */
                        if (index != 0 && index <= 15) {
                            if ((index % 15) == 0)  {
                                Console.Write("  ");
                                Console.Write(radek);
                                konec=radek;
                                radek = "";
                                Console.WriteLine();
                                byteValues = byteValues +16;
                                Console.Write("0x");
                                Console.Write(byteValues.ToString("x4"));
                                Console.Write(": ");
                            } 

                            /*vypsani mezery mezi 8 a 9 prvkem */
                            if ((index % 7) == 0 && index != 14)  {
                                Console.Write(" ");
                            }
                        }

                        /*uchovani posledniho radku */
                        konec = radek;
                    }

                    /*formatovani posledniho radku */
                    if (konec != "")
                    {
                        konec = " " + konec;
                    }
                    /* uprava formatovani posledniho radku */
                    int turblen = konec.Length;
                    if (turblen >= 8)
                        turblen--;
                    /*vypocetni aritmetika pro odradkovani */
                    int pocet_mezer = (48 - (3*turblen));
                    if (pocet_mezer >= 27) {
                        if (konec.Length != 8) {
                            pocet_mezer = pocet_mezer+3;
                        }
                    }
                    /*oprava pro pocet mezer */
                    else if (pocet_mezer >=24 && pocet_mezer <=26) {
                        
                    }
                    /* defaultni hodnota */
                    else {
                        pocet_mezer = pocet_mezer+2;
                    }
                    /*tisknuti mezer */
                    while (pocet_mezer != -2) {
                        Console.Write(" ");
                        pocet_mezer = pocet_mezer-1;
                    }
                    
                    /*vypis posledniho radku */
                    Console.Write(konec);
                    konec = "";

                    /*formatovani */
                    Console.WriteLine();

                    /*formatovani */
                    Console.WriteLine();

                    /*podminka pro kontrolu vypsani potrebneho poctu paketu */
                    paketky++;
                    if (paketky == pocet_paketu)
                        break;
                }
                /*odchytavani spatnych paketu */
                catch { 
                    continue;
                }
            }
            /*Uzavre spojeni se zarizenim */
            device.Close();
        }
    }
}

