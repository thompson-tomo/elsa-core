using Elsa.Common.Entities;

namespace Elsa.Identity.Entities;

/// <summary>
/// Represents an application.
/// </summary>
public class Application : Entity
{
    /// <summary>
    /// The client ID.
    /// </summary>
    public string ClientId { get; set; } = null!;
    
    /// <summary>
    /// The hashed client secret.
    /// </summary>
    public string HashedClientSecret { get; set; } = null!;

    /// <summary>
    /// The hashed client secret salt.
    /// </summary>
    public string HashedClientSecretSalt { get; set; } = null!;
    
    /// <summary>
    /// Gets or sets the name.
    /// </summary>
    public string Name { get; set; } = null!;

    /// <summary>
    /// Gets or sets the hashed password.
    /// </summary>
    public string HashedApiKey { get; set; } = null!;

    /// <summary>
    /// Gets or sets the hashed password salt.
    /// </summary>
    public string HashedApiKeySalt { get; set; } = null!;

    /// <summary>
    /// Gets or sets the roles.
    /// </summary>
    public ICollection<string> Roles { get; set; } = new List<string>();
}