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

namespace IS.View
{
    /// <summary>
    /// Interaction logic for Home.xaml
    /// </summary>
    public partial class Home : Window, INotifyPropertyChanged
    {
        static string path = AppDomain.CurrentDomain.BaseDirectory.ToString();
        InformationSecurityContext ISContext = new InformationSecurityContext();
        FileStream fs = File.Create($"{path}\\CPE&CVEBind.txt");
       List <double> scoreList=new List<double>();
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

        private async void btnLogin_Click(object sender, RoutedEventArgs e)
        {
            FileStream fs = File.Create($"{path}\\CPE&CVEBind.txt");
            fs.Close();
            string registry_key = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
            using (RegistryKey key = Registry.LocalMachine.OpenSubKey(registry_key))
            {
                //IndeterminateProgressWindow.GlobalBackground = Brushes.White;
                //IndeterminateProgressWindow.GlobalForeground = Brushes.Black;


                // Circular.Progress = i;
                //sfCircular.SegmentCount = 1;
                //sfCircular.Visibility = Visibility.Visible;
                //sfCircular.ShowProgressValue = true;
                var win = new IndeterminateProgressWindow("Please wait while we are scaning  your computer. . .");
                win.Show();
                //Do Some Staff
                //Change the message the 2nd time

                foreach (string subkey_name in key.GetSubKeyNames())
                {
                    using (RegistryKey subkey = key.OpenSubKey(subkey_name))
                    {
                        win.Close();
                        win.Visibility = Visibility.Hidden;
                        win = new IndeterminateProgressWindow($"{i}from {key.GetSubKeyNames().Length}");
                        //  win.Message =;
                        //iCount = (i * 100) / key.SubKeyCount;
                        win.Show();
                        i++;
                        //QModernMessageBox.Show($"{i}from {key.GetSubKeyNames().Length}", "Loading", QModernMessageBox.QModernMessageBoxButtons.Ok, ModernMessageboxIcons.Info, true);
                        if (!String.IsNullOrEmpty((string?)subkey.GetValue("DisplayName")))
                        {
                            string word = "";
                            if (subkey.GetValue("DisplayName").ToString().Split().Length > 1) { 
                             word = subkey.GetValue("DisplayName").ToString().Split(' ')[0] + " " + subkey.GetValue("DisplayName").ToString().Split(' ')[1];
                            }
                            else {
                                word = subkey.GetValue("DisplayName").ToString().Split(' ')[0];
                                    }
                          await  LoadCPE(word);
                        }

                    }
                    if (i >= key.GetSubKeyNames().Length) {
                        // MessageBox.Show("finshed");
                        win.Close();
                        win.Visibility = Visibility.Hidden;
                        win.Message = $"finshed";
                        win.Show();
                        win.Close();
                        i = 0;
                        QModernMessageBox.Done($"finshed please check CPE&CVEBind.txt with score {scoreList.Max()}", "Done");
                        scoreList.Clear();
                        //  fs.Close();
                    }
                }
            }
        }
        private async Task LoadCPE(string name)
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
                    var response =
                         client.GetAsync($"2.0?keywordSearch={name}&resultsPerPage=1");
                    client.DefaultRequestHeaders.Add("apiKey", $"{apiKey}");
                  response.Wait();
                    var result = response.Result;

                    result.EnsureSuccessStatusCode();
                  

                    // deserialize to a list 
                    //IList<Root> ls =
                    //    await response.Content.ReadAsAsync<IList<Root>>();
                    Root root = await result.Content.ReadAsAsync<Root>();
                    //Console.WriteLine(root.products.FirstOrDefault().cpe.cpeName);
                    if (root.products.FirstOrDefault() != null) { 
                    string cpeName = root.products.FirstOrDefault().cpe.cpeName ?? "";


                       // System.Threading.Thread.Sleep(6000);

                        LoadCVE(name, cpeName, root);
                    }


                }

                catch (Exception ex)
                {
                     System.Threading.Thread.Sleep(1000*10);

                    //MessageBox.Show(ex.Message);

                }

            }

        }
        private async void LoadCVE(string name,string cpeName,Root rootPass)
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
                    var response =
                         client.GetAsync($"?cpeName={cpeName}&resultsPerPage=1");
                        client.DefaultRequestHeaders.Add("apiKey", $"{apiKey}");
                        response.Wait();
                    var result = response.Result;

                    result.EnsureSuccessStatusCode();


                    // deserialize to a list 
                    //IList<Root> ls =
                    //    await response.Content.ReadAsAsync<IList<Root>>();
                    RootCVE root = await result.Content.ReadAsAsync<RootCVE>();
                        //Console.WriteLine(root.products.FirstOrDefault().cpe.cpeName);
                        var varn= root.vulnerabilities.FirstOrDefault();
                        Configuration? confVar=null;
                        Node? nodesVar = null;
                        CpeMatch? cpeMatchVar = null;
                        string? cveVar = "false";
                        if (varn != null) { 
                         confVar = varn.cve.configurations.FirstOrDefault();
                        }
                        if (confVar != null) { 
                         nodesVar = confVar.nodes.FirstOrDefault();
                        }
                        if (nodesVar != null) {
                           cpeMatchVar = nodesVar.cpeMatch.FirstOrDefault();
                        }
                        if (cpeMatchVar != null) { 
                         cveVar = cpeMatchVar.vulnerable.ToString();
                        }
                        string? cveName = cveVar;



                    Cpe23 cpe23 = new Cpe23 { CpeName =cpeName, CpeTitle = name, Cve = cveName };
                    ISContext.Add(cpe23);
                    ISContext.SaveChanges();
                        using (var writer = File.AppendText($"{path}\\CPE&CVEBind.txt"))
                        { string dataCPE = JsonSerializer.Serialize(rootPass).ToString();
                            string dataCVE = JsonSerializer.Serialize(root).ToString();
                            writer.Write($"{dataCPE}\n");
                            writer.Write($"\n");
                            writer.Write($"{dataCVE}\n");
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
                    //MessageBox.Show(ex.Message);

                }

            }

        }
    }
   
}
