using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.EntityFrameworkCore;

namespace IS.Entity
{
    public partial class User
    {
        [Key]
        [Column("user_id")]
        public int UserId { get; set; }
        [Column("username")]
        [StringLength(100)]
        public string Username { get; set; } = null!;
        [Column("password")]
        [StringLength(8)]
        public string Password { get; set; } = null!;
    }
}
