using System.Text.Json;
using System.Text.Json.Serialization;
using Elsa.Common.Services;
using Elsa.EntityFrameworkCore.Common;
using Elsa.Workflows.Core.Models;
using Elsa.Workflows.Core.Serialization;
using Elsa.Workflows.Core.Serialization.Converters;
using Elsa.Workflows.Core.State;
using Elsa.Workflows.Runtime.Services;
using Microsoft.EntityFrameworkCore;

namespace Elsa.EntityFrameworkCore.Modules.Runtime;

/// <inheritdoc />
public class EFCoreWorkflowStateStore : IWorkflowStateStore
{
    private readonly SerializerOptionsProvider _serializerOptionsProvider;
    private readonly ISystemClock _systemClock;
    private readonly IDbContextFactory<RuntimeElsaDbContext> _dbContextFactory;
    private readonly EntityStore<RuntimeElsaDbContext, WorkflowState> _store;

    /// <summary>
    /// Constructor.
    /// </summary>
    public EFCoreWorkflowStateStore(
        EntityStore<RuntimeElsaDbContext, WorkflowState> store,
        IDbContextFactory<RuntimeElsaDbContext> dbContextFactory,
        SerializerOptionsProvider serializerOptionsProvider,
        ISystemClock systemClock)
    {
        _serializerOptionsProvider = serializerOptionsProvider;
        _systemClock = systemClock;
        _dbContextFactory = dbContextFactory;
        _store = store;
    }

    /// <inheritdoc />
    public async ValueTask SaveAsync(string id, WorkflowState state, CancellationToken cancellationToken = default) => 
        await _store.SaveAsync(state, Save, cancellationToken: cancellationToken);

    /// <inheritdoc />
    public async ValueTask<WorkflowState?> LoadAsync(string id, CancellationToken cancellationToken = default)
    {
        await using var dbContext = await _dbContextFactory.CreateDbContextAsync(cancellationToken);
        var options = _serializerOptionsProvider.CreatePersistenceOptions(ReferenceHandler.Preserve);
        var entity = await dbContext.WorkflowStates.FirstOrDefaultAsync(x => x.Id == id, cancellationToken);

        if (entity == null)
            return null;

        var entry = dbContext.Entry(entity);
        var json = entry.Property<string>("Data").CurrentValue;

        // For reading string:object dictionaries where the objects would otherwise be read as JsonElement values.
        options.Converters.Add(new SystemObjectPrimitiveConverter());
        return JsonSerializer.Deserialize<WorkflowState>(json, options);
    }

    /// <inheritdoc />
    public async ValueTask<int> CountAsync(CountRunningWorkflowsArgs args, CancellationToken cancellationToken = default)
    {
        await using var dbContext = await _dbContextFactory.CreateDbContextAsync(cancellationToken);
        var query = dbContext.WorkflowStates.AsQueryable().Where(x => x.Status == WorkflowStatus.Running);

        if (args.DefinitionId != null) query = query.Where(x => x.DefinitionId == args.DefinitionId);
        if (args.Version != null) query = query.Where(x => x.DefinitionVersion == args.Version);
        if (args.CorrelationId != null) query = query.Where(x => x.CorrelationId == args.CorrelationId);

        return await query.CountAsync(cancellationToken);
    }
    
    private WorkflowState Save(RuntimeElsaDbContext dbContext, WorkflowState entity)
    {
        var options = _serializerOptionsProvider.CreatePersistenceOptions(ReferenceHandler.Preserve);
        var json = JsonSerializer.Serialize(entity, options);
        var now = _systemClock.UtcNow;
        var entry = dbContext.Entry(entity);

        if (entry.Property<DateTimeOffset>("CreatedAt").CurrentValue == DateTimeOffset.MinValue)
            entry.Property<DateTimeOffset>("CreatedAt").CurrentValue = now;

        entry.Property<string>("Data").CurrentValue = json;
        entry.Property<DateTimeOffset>("UpdatedAt").CurrentValue = now;

        dbContext.Entry(entity).Property("Data").CurrentValue = json;
        return entity;
    }
}