using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;
using IS.DTOS;
using System.Text.Json.Nodes;
using System.Net.Http.Headers;
using IS.Models;
using System.IO;
using System.Text.Json;
using static System.Net.WebRequestMethods;
using File = System.IO.File;
using System.Diagnostics;
using ModernMessageBoxLib;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using static System.Formats.Asn1.AsnWriter;
using IS.Model;
using System.Xml.Linq;
using System.Xml.XPath;
using System.Security.Cryptography;

namespace IS.View
{
    /// <summary>
    /// Interaction logic for Home.xaml
    /// </summary>
    public partial class Home : Window, INotifyPropertyChanged
    {
        static string path = AppDomain.CurrentDomain.BaseDirectory.ToString();
        CPEVM vm = new CPEVM();
        InformationSecurityContext ISContext = new InformationSecurityContext();
        FileStream fs = File.Create($"{path}\\CPE&CVEBind.txt");
       List <double> scoreList=new List<double>();
        Dictionary<string,string> cweDic = new Dictionary<string,string>();
        private int i = 0;
        private double _iCount;
        public double iCount
        {
            get { return _iCount; }
            set
            {
                _iCount = value;
                OnPropertyChanged();
            }
        }
        private double _Max;
        public double max
        {
            get { return _Max; }
            set
            {
                _Max = value;
                OnPropertyChanged();
            }
        }
        int count = 0;
        string apiKey = "fc9f1445-c1aa-43d4-951f-a07cd18b8591";

        public event PropertyChangedEventHandler? PropertyChanged;
        protected void OnPropertyChanged([CallerMemberName] string propertyName = null)
        {
            PropertyChangedEventHandler handler = this.PropertyChanged;
            if (handler != null)
            {
                var e = new PropertyChangedEventArgs(propertyName);
                handler(this, e);
            }
        }
        public Home()
        {
            
            ServicePointManager.Expect100Continue = true;
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            fs.Close();
            InitializeComponent();
            DataContext = this;
            try
            {
                foreach (var item in ISContext.Cpe23s)
                {
                    ISContext.Remove(item);
                }
                ISContext.SaveChanges();
            }
            catch (Exception)
            {

               
            }
           

        }
        private void Window_MouseDown(object sender, MouseButtonEventArgs e)
        {
            if (e.LeftButton == MouseButtonState.Pressed)
                DragMove();
        }

        private void btnMinimize_Click(object sender, RoutedEventArgs e)
        {
            WindowState = WindowState.Minimized;
        }

        private void btnClose_Click(object sender, RoutedEventArgs e)
        {
            Application.Current.Shutdown();
        }
        /// <summary>
        ///  this method for create new thread to search for the CPE and cve and worte in the file with insialize threads
        /// </summary>
        private async void btnLogin_Click(object sender, RoutedEventArgs e)
        {
            BackgroundWorker worker = new BackgroundWorker();
            worker.WorkerReportsProgress = true;
            worker.DoWork += worker_DoWork;
            //worker.ProgressChanged += worker_ProgressChanged;
            worker.RunWorkerCompleted += worker_RunWorkerCompleted;
            worker.RunWorkerAsync(10000000);
            
        }

        private void worker_RunWorkerCompleted(object? sender, RunWorkerCompletedEventArgs e)
        {
            using (var writer = File.AppendText($"{path}\\CPE&CVEBind.txt"))
            {
                writer.Write($"------------------------------------------------------\n");
                writer.Write($"------------------------------------------------------\n");
                writer.Write($"------------------------------------------------------\n");
                writer.Write($"------------------------------------------------------\n");
                //fs.Close();
            }
            foreach (var item in cweDic)
            {
                string WeaknessName = GetAddress(item.Value, "1000.csv");
                if (WeaknessName == "")
                {
                    WeaknessName = GetAddress(item.Value, "699.csv");
                }
                if (WeaknessName == "")
                {
                    WeaknessName = GetAddress(item.Value, "1194.csv");
                }
                using (var writer = File.AppendText($"{path}\\CPE&CVEBind.txt"))
                {
                    writer.Write($" weakness of the product{item.Key}with weakness{WeaknessName} with weakness Id {item.Value} \n");
                  //  writer.Write($"------------------------------------------------------\n");
                    //fs.Close();
                }
                (string cpeacName, string cpeacDisc) = GetAddressCPAEC(item.Value, "2000.csv");
                using (var writer = File.AppendText($"{path}\\CPE&CVEBind.txt"))
                {
                    writer.Write($" cpeac of the product{item.Key}with name {cpeacName} and discription {cpeacDisc}\n");
                    writer.Write($"------------------------------------------------------\n");
                    //fs.Close();
                }
            }
            
            QModernMessageBox.Done($"finshed please check CPE&CVEBind.txt with score {scoreList.Max()}", "Done");
            scoreList.Clear();

        }
        String GetAddress(String searchName, string filename)
        {
            var strLines = File.ReadLines($"{path}/weakness/{filename}");
            foreach (var line in strLines)
            {
                if (line.Split(',')[0].Equals(searchName))
                    return line.Split(',')[1];
            }

            return "";
        }
        (string, string) GetAddressCPAEC(String searchName, string filename)
        {
            int a;
            int b=0;
            var strLines = File.ReadLines($"{path}/weakness/{filename}");
            int.TryParse(searchName, out a);
            if (a ==0)
            {
                return ("","");
            }
            foreach (var line in strLines)
            {
                var arraySearch = line.Split(',');
                foreach (var item in arraySearch[17].Split("::"))
                {
                    if (item.Equals(searchName,StringComparison.CurrentCultureIgnoreCase))
                    {
                        return (line.Split(',')[1], line.Split(',')[4]);
                    }
                //    int.TryParse(item, out b);
                //    if (b==0)
                //    {
                //        continue;
                //    }
                //    if (a == b) {
                //        Console.WriteLine($"searchitem={a},searchitem={b}");
                //        return line.Split(',')[4]; 
                //    }

            }
            //if (line.Split(',')[17]. Contains(searchName))
            //    return line.Split(',')[4];
        }

            return ("", "");
        }
        /// <summary>
        ///  this method for searching for the programs in our operating system that's found in the registery file
        ///  it searches for the name and then split it and search the parts to be find in cpe
        /// </summary>
        void worker_DoWork(object sender, DoWorkEventArgs e)
        {
            FileStream fs = File.Create($"{path}\\CPE&CVEBind.txt");
            fs.Close();
            string registry_key = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
            using (RegistryKey key = Registry.LocalMachine.OpenSubKey(registry_key))
            {

                vm.ICount = i;
                max = key.SubKeyCount;
                foreach (string subkey_name in key.GetSubKeyNames())
                {
                    using (RegistryKey subkey = key.OpenSubKey(subkey_name))
                    {
                        i++;
                        iCount = i;

                        if (!String.IsNullOrEmpty((string?)subkey.GetValue("DisplayName")))
                        {
                            string word = "";
                            if (subkey.GetValue("DisplayName").ToString().Split().Length > 1)
                            {
                                word = subkey.GetValue("DisplayName").ToString().Split(' ')[0] + " " + subkey.GetValue("DisplayName").ToString().Split(' ')[1];
                            }
                            else
                            {
                                word = subkey.GetValue("DisplayName").ToString().Split(' ')[0];
                            }
                             LoadCPE(word, subkey.GetValue("DisplayName").ToString());
                        }

                    }
                    if (i >= key.GetSubKeyNames().Length)
                    {
                        i = 0;
                    }
                }
            }
        }
        /// <summary>
        ///  this method for searching in the cpe api to be find in your computer then it go to the CVE if the CPE APi
        ///  return 403 forbbiden then i wate for 10 secounds so the server can reset so i can search again as it is mentioned in the cpe doc
        /// </summary>
        private async void LoadCPE(string name,string product)
        {

            // make an API request 
            using (HttpClient client = new HttpClient())

            {
                client.DefaultRequestHeaders.Accept.Add(
        new MediaTypeWithQualityHeaderValue("application/json"));
                try
                {
                    //System.Threading.Thread.Sleep(6000);

                    client.BaseAddress = new Uri("https://services.nvd.nist.gov/rest/json/cpes/");
                    client.DefaultRequestHeaders.Add("apiKey", $"{apiKey}");
                    var response =
                         client.GetAsync($"2.0?keywordSearch={name}&resultsPerPage=1");
                  response.Wait();
                    var result = response.Result;

                    result.EnsureSuccessStatusCode();
                  
                    Root root = await result.Content.ReadAsAsync<Root>();
                    if (root.products.FirstOrDefault() != null) { 
                    string cpeName = root.products.FirstOrDefault().cpe.cpeName ?? "";



                         LoadCVE(name, cpeName, root, product);
                    }


                }

                catch (Exception ex)
                {
                     System.Threading.Thread.Sleep(1000*10);


                }

            }

        }
        /// <summary>
        ///  this method for searching in the CVE api to be find in your computer then it write in the file and the database
        ///  return 403 forbbiden then i wate for 10 secounds so the server can reset so i can search again as it is mentioned in the CVE doc
        /// </summary>
        private async void LoadCVE(string name,string cpeName,Root rootPass,string product)
        {

            // make an API request 
            using (HttpClient client = new HttpClient())

            {
                client.DefaultRequestHeaders.Accept.Add(
        new MediaTypeWithQualityHeaderValue("application/json"));
                try
                {
                    if (!string.IsNullOrEmpty(cpeName))
                    {

                    
                    client.BaseAddress = new Uri("https://services.nvd.nist.gov/rest/json/cves/2.0");
                        client.DefaultRequestHeaders.Add("apiKey", $"{apiKey}");
                        var response =
                         client.GetAsync($"?cpeName={cpeName}&resultsPerPage=1");
                        response.Wait();
                    var result = response.Result;

                    result.EnsureSuccessStatusCode();


                    
                    RootCVE root = await result.Content.ReadAsAsync<RootCVE>();
                        var varn= root.vulnerabilities.FirstOrDefault();
                        Description? decVar=null;
                        string? valueVar = null;
                        CpeMatch? cpeMatchVar = null;
                        string? cveVar = "";
                        string cweKey = "";
                        if (varn != null) {

                            decVar = varn.cve.descriptions.FirstOrDefault();
                            if (varn.cve.weaknesses.FirstOrDefault() != null)
                            {
                              cweKey = varn.cve.weaknesses.FirstOrDefault().description.FirstOrDefault().value.Split('-')[1];
                                cweDic.Add(product,cweKey);
                            }
                        }
                        if (decVar != null) {
                            valueVar = decVar.value;
                        }
                        //if (valueVar != null) {
                        //   cpeMatchVar = valueVar.cpeMatch.FirstOrDefault();
                        //}
                        //if (cpeMatchVar != null) { 
                        // cveVar = cpeMatchVar.vulnerable.ToString();
                        //}
                        string ? cveName = valueVar;

                       
                        //XDocument doc = XDocument.Load($"{path}/weakness/cwec_v4.9.xml");
                        //XNamespace ns = "http://cwe.mitre.org/cwe-6";
                        //var weakn = from weakness in doc.Elements("Weaknesses").SelectMany(e => e.Elements("Weakness"))
                        //where weakness.Attribute("ID").Value == cweKey
                        //select weakness.Parent;
                        ////var weakn =  from weakness in doc.Root.Elements(ns + "Weakness").Descendants(ns + "Weaknesses") 
                        ////             where weakness.Attribute("ID").Value == cweKey
                        ////             select weakness.ToString();
                        //var results = doc.Root.Elements(ns + "Weakness").Descendants(ns + "Weaknesses").ToList();

                        Cpe23 cpe23 = new Cpe23 { CpeName =cpeName, CpeTitle = name, Cve = cveName,Product= product };
                    ISContext.Add(cpe23);
                    ISContext.SaveChanges();
                        using (var writer = File.AppendText($"{path}\\CPE&CVEBind.txt"))
                        {
                            string dataCPE = JsonSerializer.Serialize(rootPass).ToString();
                            string dataCVE = JsonSerializer.Serialize(root).ToString();
                            writer.Write($"the product is :{product}\n");
                            writer.Write($"{rootPass.products.FirstOrDefault().cpe.cpeName}\n");
                            writer.Write($"\n");
                            writer.Write($"{dataCVE}\n");
                            //writer.Write($"\n");
                            //writer.Write($"{cweDic.LastOrDefault()}\n");
                            writer.Write($"------------------------------------------------------\n");

                            //fs.Close();
                        }
                        if (varn != null) {
                            scoreList.Add(root.vulnerabilities.FirstOrDefault().cve.metrics.cvssMetricV2.FirstOrDefault().exploitabilityScore);
                            count++;
                        }
                    }
                }

                catch (Exception ex)
                {
                    System.Threading.Thread.Sleep(1000 * 10);

                }

            }
      
        }
    }
   
}
