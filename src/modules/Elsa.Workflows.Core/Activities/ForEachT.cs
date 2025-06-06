using System.Runtime.CompilerServices;
using Elsa.Expressions.Models;
using Elsa.Extensions;
using Elsa.Workflows.Attributes;
using Elsa.Workflows.Behaviors;
using Elsa.Workflows.Memory;
using Elsa.Workflows.Models;

namespace Elsa.Workflows.Activities;

/// <summary>
/// A strongly-typed for-each construct where <see cref="T"/> is the item type.
/// </summary>
public class ForEach<T> : Activity
{
    private const string CurrentIndexProperty = "CurrentIndex";

    /// <inheritdoc />
    public ForEach(Func<ExpressionExecutionContext, ICollection<T>> @delegate, [CallerFilePath] string? source = null, [CallerLineNumber] int? line = null) : this(new Input<ICollection<T>>(@delegate), source, line)
    {
    }
    
    /// <inheritdoc />
    public ForEach(Func<ICollection<T>> @delegate, [CallerFilePath] string? source = null, [CallerLineNumber] int? line = null) : this(new Input<ICollection<T>>(@delegate), source, line)
    {
    }

    /// <inheritdoc />
    public ForEach(ICollection<T> items, [CallerFilePath] string? source = null, [CallerLineNumber] int? line = null) : this(new Input<ICollection<T>>(items), source, line)
    {
    }
    
    /// <inheritdoc />
    public ForEach(Input<ICollection<T>> items, [CallerFilePath] string? source = null, [CallerLineNumber] int? line = null) : this(source, line)
    {
        Items = items;
    }
    
    /// <inheritdoc />
    public ForEach([CallerFilePath] string? source = null, [CallerLineNumber] int? line = null)
    {
        Behaviors.Add<BreakBehavior>(this);
    }

    /// <summary>
    /// The set of values to iterate.
    /// </summary>
    [Input(Description = "The set of values to iterate.")]
    public Input<ICollection<T>> Items { get; set; } = new(Array.Empty<T>());

    /// <summary>
    /// The activity to execute for each iteration.
    /// </summary>
    [Port]
    public IActivity? Body { get; set; }

    /// <summary>
    /// The current value being iterated will be assigned to the specified <see cref="MemoryBlockReference"/>.
    /// </summary>
    [Output(Description = "Assign the current value to the specified variable.")]
    public Output<T>? CurrentValue { get; set; }

    /// <inheritdoc />
    protected override async ValueTask ExecuteAsync(ActivityExecutionContext context)
    {
        // Execute first iteration.
        await HandleIteration(context);
    }

    private async Task HandleIteration(ActivityExecutionContext context)
    {
        var isBreaking = context.GetIsBreaking();
        
        if (isBreaking)
        {
            await context.CompleteActivityAsync();
            return;
        }
        
        var currentIndex = context.GetProperty<int>(CurrentIndexProperty);
        var items = context.Get(Items)!.ToList();

        if (currentIndex >= items.Count)
        {
            await context.CompleteActivityAsync();
            return;
        }

        var currentValue = items[currentIndex];
        context.Set(CurrentValue, currentValue);

        if (Body != null)
        {
            var variables = new[]
            {
                new Variable("CurrentIndex", currentIndex),
                new Variable("CurrentValue", currentValue)
            };
            await context.ScheduleActivityAsync(Body, OnChildCompleted, variables: variables);
        }
        else
            await context.CompleteActivityAsync();

        // Increment index.
        context.UpdateProperty<int>(CurrentIndexProperty, x => x + 1);
    }

    private async ValueTask OnChildCompleted(ActivityCompletedContext context)
    {
        await HandleIteration(context.TargetContext);
    }
}