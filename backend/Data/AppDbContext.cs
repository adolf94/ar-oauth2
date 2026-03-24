using Microsoft.EntityFrameworkCore;
using backend.Models;

namespace backend.Data
{
    public class AppDbContext : DbContext
    {
        public DbSet<Client> Clients { get; set; } = null!;
        public DbSet<User> Users { get; set; } = null!;
        public DbSet<Token> Tokens { get; set; } = null!;
        public DbSet<RoleDefinition> RoleDefinitions { get; set; } = null!;
        public DbSet<AuthCode> AuthCodes { get; set; } = null!;
        public DbSet<ApplicationScope> ApplicationScopes { get; set; } = null!;
        public DbSet<UserClientScope> UserClientScopes { get; set; } = null!;
        public DbSet<CrossAppTrust> CrossAppTrusts { get; set; } = null!;
        public DbSet<LogEntry> Logs { get; set; } = null!;

        public AppDbContext(DbContextOptions<AppDbContext> options)
            : base(options)
        {
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<Client>().ToContainer("Clients").HasPartitionKey(c => c.Id);
            modelBuilder.Entity<User>().ToContainer("Users").HasPartitionKey(u => u.Id);
            modelBuilder.Entity<Token>().ToContainer("Tokens").HasPartitionKey(t => t.Id);
            modelBuilder.Entity<RoleDefinition>().ToContainer("RoleDefinitions").HasPartitionKey(r => r.ClientId);
            modelBuilder.Entity<AuthCode>().ToContainer("AuthCodes").HasPartitionKey(a => a.Id);
            modelBuilder.Entity<ApplicationScope>().ToContainer("ApplicationScopes").HasPartitionKey(s => s.ClientId);
            modelBuilder.Entity<UserClientScope>().ToContainer("UserClientScopes").HasPartitionKey(u => u.UserId);
            modelBuilder.Entity<CrossAppTrust>().ToContainer("CrossAppTrusts").HasPartitionKey(t => t.RequestingClientId);
            modelBuilder.Entity<LogEntry>().ToContainer("Logs").HasPartitionKey(l => l.Id);
        }
    }
}
