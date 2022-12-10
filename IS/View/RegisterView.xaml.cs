using IS.Entity;
using ModernMessageBoxLib;
using System;
using System.Collections.Generic;
using System.Data.Entity;
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
    /// Interaction logic for RegisterView.xaml
    /// </summary>
    public partial class RegisterView : Window
    {
        InformationSecurityContext ISContext = new InformationSecurityContext();

        public RegisterView()
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
        private void Register_Click(object sender, RoutedEventArgs e)
        {
            if (!txtPass.Password.Equals(txtRepeatePass.Password))
            {
                QModernMessageBox.Error("password doesn't match", "Error");

            }
            else
            {
                var userFound = ISContext.Users.FirstOrDefault(x => x.Username.Equals(txtUser.Text.Trim()));
                if (userFound ==null)
                {
                    var x = ISContext.Users.Add(new User { Username = txtUser.Text.Trim(), Password = txtPass.Password });
                    ISContext.SaveChanges();
                    QModernMessageBox.Done("Sucssefully added a new user", "UserAdded ");

                    LoginView login = new LoginView();
                    this.Close();
                    login.Show();

                }
                else {
                    QModernMessageBox.Error("their is a user name with the same UserName", "Error");

                }
            }
        }
    }
}
