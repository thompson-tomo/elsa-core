using System.Reflection;

namespace Elsa.Workflows.Management.Services;

public interface IPropertyDefaultValueResolver
{
    object? GetDefaultValue(PropertyInfo activityPropertyInfo);
}