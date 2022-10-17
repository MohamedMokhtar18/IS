using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IS.DTOS
{
    public class Root
    {
        public int resultsPerPage { get; set; }
        public int startIndex { get; set; }
        public int totalResults { get; set; }
        public string format { get; set; }
        public string version { get; set; }
        public DateTime timestamp { get; set; }
        public List<Product> products { get; set; }
    }
}
