using IS.Entity;
using ModernMessageBoxLib;
using System;
using System.Collections.Generic;
using System.Linq;
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

namespace IS.View
{
    /// <summary>
    /// Interaction logic for LoginView.xaml
    /// </summary>
    public partial class LoginView : Window
    {
        InformationSecurityContext ISContext = new InformationSecurityContext();

        public LoginView()
        {
            InitializeComponent();
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
        ///  this method for searching of hte acount in the database  to match with the data input
        ///  and if it is true then you will be sending to the home page (Scan page)
        /// </summary>
        private void btnLogin_Click(object sender, RoutedEventArgs e)
        {
            foreach (var item in ISContext.Users)
            {
                if (txtUser.Text.Equals(item.Username.Trim(), StringComparison.CurrentCultureIgnoreCase) && txtPass.Password.Equals(item.Password))
                {
                    Home home = new Home();
                    this.Close();
                    home.Show();
                }
                else
                {
                    QModernMessageBox.Error("Username or password invalid", "Error");
                }
                
            }
           
        }
    }
}
