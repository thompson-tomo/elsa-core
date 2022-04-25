using System.Text.Json;
using System.Text.Json.Serialization;
using Elsa.Services;

namespace Elsa.Management.Models;

public class ActivityDescriptor
{
    public string ActivityType { get; init; } = default!;
    public string Category { get; init; } = default!;
    public string? DisplayName { get; init; }
    public string? Description { get; init; }
    public ICollection<InputDescriptor> InputProperties { get; init; } = new List<InputDescriptor>();
    public ICollection<OutputDescriptor> OutputProperties { get; init; } = new List<OutputDescriptor>();

    [JsonIgnore] public Func<ActivityConstructorContext, IActivity> Constructor { get; init; } = default!;
    public ActivityTraits Traits { get; set; } = ActivityTraits.Action;
    public ICollection<Port> InPorts { get; init; } = new List<Port>();
    public ICollection<Port> OutPorts { get; init; } = new List<Port>();
}

public record ActivityConstructorContext(JsonElement Element, JsonSerializerOptions SerializerOptions);