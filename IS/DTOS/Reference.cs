using System.Collections.Generic; 
namespace IS.DTOS{ 

    public class Reference
    {
        public string url { get; set; }
        public string source { get; set; }
        public List<string> tags { get; set; }
    }

}