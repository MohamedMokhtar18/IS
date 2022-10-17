using System.Collections.Generic; 
namespace IS.DTOS{ 

    public class Weakness
    {
        public string source { get; set; }
        public string type { get; set; }
        public List<Description> description { get; set; }
    }

}