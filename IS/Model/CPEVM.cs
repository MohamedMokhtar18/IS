using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IS.Model
{
    public class CPEVM : INotifyPropertyChanged
    {
        private double _iCount;

        public double ICount { get => _iCount; set
            {
                _iCount = value;
                OnPropertyChanged("ICount");
            }
        }

        public event PropertyChangedEventHandler? PropertyChanged;
        private void OnPropertyChanged(string propertyName)
        {
            if (PropertyChanged != null)
            {
                PropertyChanged(this, new PropertyChangedEventArgs(propertyName));
            }
        }
    }
}
