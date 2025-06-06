using Elsa.Expressions.Models;
using Elsa.Mediator.Contracts;
using Fluid;

namespace Elsa.Expressions.Liquid.Notifications;

public record RenderingLiquidTemplate(TemplateContext TemplateContext, ExpressionExecutionContext Context) : INotification;