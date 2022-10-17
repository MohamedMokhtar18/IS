using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.EntityFrameworkCore;

namespace IS.Entity
{
    [Table("CPE23")]
    public partial class Cpe23
    {
        [Column("CPE_name")]
        public string? CpeName { get; set; }
        [Column("CPE_title")]
        public string? CpeTitle { get; set; }
        [Column("CVE")]
        public string? Cve { get; set; }
        [Key]
        [Column("CPE_Id")]
        public int CpeId { get; set; }
    }
}
