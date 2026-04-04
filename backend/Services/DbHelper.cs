using System.Threading.Tasks;
using backend.Data;

namespace backend.Services
{
    public class DbHelper : IDbHelper
    {
        private readonly AppDbContext _context;
        private bool _isBatching = false;

        public DbHelper(AppDbContext context)
        {
            _context = context;
        }

        public async Task SaveChangesAsync(bool force = true)
        {
            if (force || !_isBatching)
            {
                await _context.SaveChangesAsync();
            }
        }

        public void BeginBatch()
        {
            _isBatching = true;
        }

        public async Task CommitBatchAsync()
        {
            _isBatching = false;
            await _context.SaveChangesAsync();
        }
    }
}
