using System.Collections.Generic; 
namespace IS.DTOS{ 

    public class Configuration
    {
        public string @operator { get; set; }
        public bool negate { get; set; }
        public List<Node> nodes { get; set; }
    }

}