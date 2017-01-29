using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using System.Data.Entity;
using System.Security.Claims;
using System.Threading.Tasks;

namespace WebAPILoginWithAspNetIdentity.Models
{
    public class IdentityContext : DbContext
    {
        public class ApplicationUser : IdentityUser
        {
            public ClaimsIdentity GenerateUserIdentity(IdentityConfig.ApplicationUserManager manager)
            {
                var userIdentity = manager.CreateIdentity(this, DefaultAuthenticationTypes.ApplicationCookie);
                return userIdentity;
            }

            public Task<ClaimsIdentity> GenerateUserIdentityAsync(IdentityConfig.ApplicationUserManager manager)
            {
                return Task.FromResult(GenerateUserIdentity(manager));
            }
        }

        public IdentityContext()
            : base("Name=DefaultConnection")
        {
            Database.CommandTimeout = 120;
        }

        public static IdentityContext Create()
        {
            return new IdentityContext();
        }

        protected override void OnModelCreating(DbModelBuilder modelBuilder)
        {
            modelBuilder.Entity<ApplicationUser>()
               .ToTable("AspNetUsers")
               .HasMany(u => u.Roles).WithRequired().HasForeignKey(ur => ur.UserId);

            modelBuilder.Entity<IdentityUserRole>()
                .HasKey(r => new { r.UserId, r.RoleId })
                .ToTable("AspNetUserRoles");

            modelBuilder.Entity<IdentityUserLogin>()
                .HasKey(l => new { l.UserId, l.LoginProvider, l.ProviderKey })
                .ToTable("AspNetUserLogins");

            modelBuilder.Entity<IdentityUserClaim>()
                .ToTable("AspNetUserClaims");

            var role = modelBuilder.Entity<IdentityRole>()
                .ToTable("AspNetRoles");
            role.Property(r => r.Name).IsRequired();
            role.HasMany(r => r.Users).WithRequired().HasForeignKey(ur => ur.RoleId);
        }
    }
}