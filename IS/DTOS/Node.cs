using System.Collections.Generic; 
namespace IS.DTOS{ 

    public class Node
    {
        public string @operator { get; set; }
        public bool negate { get; set; }
        public List<CpeMatch> cpeMatch { get; set; }
    }

}