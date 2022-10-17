using System.Collections.Generic; 
using System; 
namespace IS.DTOS{ 

    public class RootCVE
    {
        public int resultsPerPage { get; set; }
        public int startIndex { get; set; }
        public int totalResults { get; set; }
        public string format { get; set; }
        public string version { get; set; }
        public DateTime timestamp { get; set; }
        public List<Vulnerability> vulnerabilities { get; set; }
    }

}