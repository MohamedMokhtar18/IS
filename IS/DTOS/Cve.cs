using System.Collections.Generic; 
using System; 
namespace IS.DTOS{ 

    public class Cve
    {
        public string id { get; set; }
        public string sourceIdentifier { get; set; }
        public DateTime published { get; set; }
        public DateTime lastModified { get; set; }
        public string vulnStatus { get; set; }
        public string evaluatorComment { get; set; }
        public List<Description> descriptions { get; set; }
        public Metrics metrics { get; set; }
        public List<Weakness> weaknesses { get; set; }
        public List<Configuration> configurations { get; set; }
        public List<Reference> references { get; set; }
    }

}