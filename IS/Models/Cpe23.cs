using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace IS.Models
{
    public partial class Cpe23
    {
        public string? CpeName { get; set; }
        public string? CpeTitle { get; set; }
        public string? Cve { get; set; }
        public int CpeId { get; set; }
    }
}
