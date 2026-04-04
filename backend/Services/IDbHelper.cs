using System.Threading.Tasks;

namespace backend.Services
{
    public interface IDbHelper
    {
        /// <summary>
        /// Saves changes to the database.
        /// </summary>
        /// <param name="force">If true (default), saves immediately even if in a batch. If false, defers saving if a batch is active.</param>
        Task SaveChangesAsync(bool force = true);

        /// <summary>
        /// Starts a batch of updates. While in a batch, SaveChangesAsync(force: false) will not persist changes.
        /// </summary>
        void BeginBatch();

        /// <summary>
        /// Persists all pending changes and ends the current batch.
        /// </summary>
        Task CommitBatchAsync();
    }
}
