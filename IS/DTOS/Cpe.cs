using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IS.DTOS
{
   public class Cpe
    {
        public bool deprecated { get; set; }
        public string cpeName { get; set; }
        public string cpeNameId { get; set; }
        public DateTime lastModified { get; set; }
        public DateTime created { get; set; }
        public List<Title> titles { get; set; }
    }
}
