using System;
using System.Collections.Generic;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata;

namespace IS.Models
{
    public partial class InformationSecurityContext : DbContext
    {
        public InformationSecurityContext()
        {
        }

        public InformationSecurityContext(DbContextOptions<InformationSecurityContext> options)
            : base(options)
        {
        }

        public virtual DbSet<Cpe23> Cpe23s { get; set; } = null!;
        public virtual DbSet<User> Users { get; set; } = null!;

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            if (!optionsBuilder.IsConfigured)
            {
#warning To protect potentially sensitive information in your connection string, you should move it out of source code. You can avoid scaffolding the connection string by using the Name= syntax to read it from configuration - see https://go.microsoft.com/fwlink/?linkid=2131148. For more guidance on storing connection strings, see http://go.microsoft.com/fwlink/?LinkId=723263.
                optionsBuilder.UseSqlServer("Server=LAPTOP-SK8H82MH\\SQLEXPRESS;User ID=admin;Password=admin;Database=InformationSecurity;Trusted_Connection=true;");
            }
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<Cpe23>(entity =>
            {
                entity.HasKey(e => e.CpeId);

                entity.ToTable("CPE23");

                entity.Property(e => e.CpeId).HasColumnName("CPE_Id");

                entity.Property(e => e.CpeName).HasColumnName("CPE_name");

                entity.Property(e => e.CpeTitle).HasColumnName("CPE_title");

                entity.Property(e => e.Cve).HasColumnName("CVE");
            });

            modelBuilder.Entity<User>(entity =>
            {
                entity.Property(e => e.UserId).HasColumnName("user_id");

                entity.Property(e => e.Password)
                    .HasMaxLength(8)
                    .HasColumnName("password");

                entity.Property(e => e.Username)
                    .HasMaxLength(100)
                    .HasColumnName("username");
            });

            OnModelCreatingPartial(modelBuilder);
        }

        partial void OnModelCreatingPartial(ModelBuilder modelBuilder);
    }
}
