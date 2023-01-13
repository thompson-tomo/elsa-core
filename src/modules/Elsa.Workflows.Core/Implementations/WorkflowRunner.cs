using Elsa.Extensions;
using Elsa.Mediator.Services;
using Elsa.Workflows.Core.Models;
using Elsa.Workflows.Core.Notifications;
using Elsa.Workflows.Core.Services;
using Elsa.Workflows.Core.State;
using Microsoft.Extensions.DependencyInjection;

namespace Elsa.Workflows.Core.Implementations;

/// <inheritdoc />
public class WorkflowRunner : IWorkflowRunner
{
    private readonly IServiceScopeFactory _serviceScopeFactory;
    private readonly IWorkflowExecutionPipeline _pipeline;
    private readonly IWorkflowStateSerializer _workflowStateSerializer;
    private readonly IWorkflowBuilderFactory _workflowBuilderFactory;
    private readonly IIdentityGenerator _identityGenerator;
    private readonly IWorkflowExecutionContextFactory _workflowExecutionContextFactory;
    private readonly IEventPublisher _eventPublisher;

    /// <summary>
    /// Constructor.
    /// </summary>
    public WorkflowRunner(
        IServiceScopeFactory serviceScopeFactory,
        IWorkflowExecutionPipeline pipeline,
        IWorkflowStateSerializer workflowStateSerializer,
        IWorkflowBuilderFactory workflowBuilderFactory,
        IIdentityGenerator identityGenerator,
        IWorkflowExecutionContextFactory workflowExecutionContextFactory,
        IEventPublisher eventPublisher)
    {
        _serviceScopeFactory = serviceScopeFactory;
        _pipeline = pipeline;
        _workflowStateSerializer = workflowStateSerializer;
        _workflowBuilderFactory = workflowBuilderFactory;
        _identityGenerator = identityGenerator;
        _workflowExecutionContextFactory = workflowExecutionContextFactory;
        _eventPublisher = eventPublisher;
    }

    /// <inheritdoc />
    public async Task<RunWorkflowResult> RunAsync(IActivity activity, RunWorkflowOptions? options = default, CancellationToken cancellationToken = default)
    {
        var workflow = Workflow.FromActivity(activity);
        return await RunAsync(workflow, options, cancellationToken);
    }

    /// <inheritdoc />
    public async Task<RunWorkflowResult> RunAsync(IWorkflow workflow, RunWorkflowOptions? options = default, CancellationToken cancellationToken = default)
    {
        var builder = _workflowBuilderFactory.CreateBuilder();
        var workflowDefinition = await builder.BuildWorkflowAsync(workflow, cancellationToken);
        return await RunAsync(workflowDefinition, options, cancellationToken);
    }

    /// <inheritdoc />
    public async Task<RunWorkflowResult<TResult>> RunAsync<TResult>(WorkflowBase<TResult> workflow, RunWorkflowOptions? options = default, CancellationToken cancellationToken = default)
    {
        var result = await RunAsync((IWorkflow)workflow, options, cancellationToken);
        return new RunWorkflowResult<TResult>(result.WorkflowState, result.Workflow, (TResult)result.Result!);
    }

    /// <inheritdoc />
    public async Task<RunWorkflowResult> RunAsync<T>(RunWorkflowOptions? options = default, CancellationToken cancellationToken = default) where T : IWorkflow
    {
        var builder = _workflowBuilderFactory.CreateBuilder();
        var workflowDefinition = await builder.BuildWorkflowAsync<T>(cancellationToken);
        return await RunAsync(workflowDefinition, options, cancellationToken);
    }

    /// <inheritdoc />
    public async Task<TResult> RunAsync<T, TResult>(RunWorkflowOptions? options = default, CancellationToken cancellationToken = default) where T : WorkflowBase<TResult>
    {
        var builder = _workflowBuilderFactory.CreateBuilder();
        var workflowDefinition = await builder.BuildWorkflowAsync<T>(cancellationToken);
        var result = await RunAsync(workflowDefinition, options, cancellationToken);
        return (TResult)result.Result!;
    }

    /// <inheritdoc />
    public async Task<RunWorkflowResult> RunAsync(Workflow workflow, RunWorkflowOptions? options = default, CancellationToken cancellationToken = default)
    {
        // Create a child scope.
        using var scope = _serviceScopeFactory.CreateScope();

        // Setup a workflow execution context.
        var instanceId = options?.InstanceId ?? _identityGenerator.GenerateId();
        var input = options?.Input;
        var correlationId = options?.CorrelationId;
        var triggerActivityId = options?.TriggerActivityId;
        var workflowExecutionContext = await CreateWorkflowExecutionContextAsync(workflow, instanceId, correlationId, default, input, default, triggerActivityId, cancellationToken);

        // Schedule the first activity.
        workflowExecutionContext.ScheduleWorkflow();

        return await RunAsync(workflowExecutionContext);
    }

    /// <inheritdoc />
    public async Task<RunWorkflowResult> RunAsync(Workflow workflow, WorkflowState workflowState, RunWorkflowOptions? options = default, CancellationToken cancellationToken = default)
    {
        // Create a child scope.
        using var scope = _serviceScopeFactory.CreateScope();

        // Create workflow execution context.
        var input = options?.Input;
        var correlationId = options?.CorrelationId ?? workflowState.CorrelationId;
        var triggerActivityId = options?.TriggerActivityId;
        var workflowExecutionContext = await CreateWorkflowExecutionContextAsync(workflow, workflowState.Id, correlationId, workflowState, input, default, triggerActivityId, cancellationToken);
        var bookmarkId = options?.BookmarkId;
        var activityId = options?.ActivityId;

        if (bookmarkId != null)
        {
            // Schedule the bookmark.
            var bookmark = workflowState.Bookmarks.FirstOrDefault(x => x.Id == bookmarkId);

            if (bookmark != null)
                workflowExecutionContext.ScheduleBookmark(bookmark);
        }
        else if (activityId != null)
        {
            // Schedule the activity.
            var activity = workflowExecutionContext.FindActivityById(activityId);
            workflowExecutionContext.ScheduleActivity(activity);
        }
        else
        {
            // Schedule the workflow itself.
            //workflowExecutionContext.ScheduleRoot();
            workflowExecutionContext.ScheduleWorkflow();
        }

        return await RunAsync(workflowExecutionContext);
    }

    /// <inheritdoc />
    public async Task<RunWorkflowResult> RunAsync(WorkflowExecutionContext workflowExecutionContext)
    {
        var workflow = workflowExecutionContext.Workflow;
        var cancellationToken = workflowExecutionContext.CancellationToken;
        
        // Publish domain event.
        await _eventPublisher.PublishAsync(new WorkflowExecuting(workflow), cancellationToken);
        
        // Transition into the Running state.
        workflowExecutionContext.TransitionTo(WorkflowSubStatus.Executing);

        // Execute the workflow execution pipeline.
        await _pipeline.ExecuteAsync(workflowExecutionContext);

        // Extract workflow state.
        var workflowState = _workflowStateSerializer.SerializeState(workflowExecutionContext);

        // Read captured output, if any.
        var result = workflow.ResultVariable?.Get(workflowExecutionContext.MemoryRegister);
        
        // Publish domain event.
        await _eventPublisher.PublishAsync(new WorkflowExecuted(workflow, workflowState), cancellationToken);
        
        // Return workflow execution result containing state + bookmarks.
        return new RunWorkflowResult(workflowState, workflowExecutionContext.Workflow, result);
    }

    private async Task<WorkflowExecutionContext> CreateWorkflowExecutionContextAsync(
        Workflow workflow,
        string instanceId,
        string? correlationId,
        WorkflowState? workflowState,
        IDictionary<string, object>? input,
        ExecuteActivityDelegate? executeActivityDelegate,
        string? triggerActivityId,
        CancellationToken cancellationToken) =>
        await _workflowExecutionContextFactory.CreateAsync(workflow, instanceId, workflowState, input, correlationId, executeActivityDelegate, triggerActivityId, cancellationToken);
}