// Copyright (c) Microsoft. All rights reserved.
namespace Microsoft.Azure.Devices.Edge.Hub.Http.controllers
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using Microsoft.AspNetCore.Authorization.Infrastructure;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Mvc.Abstractions;
    using Microsoft.AspNetCore.Mvc.Authorization;
    using Microsoft.AspNetCore.Mvc.Infrastructure;
    using Microsoft.AspNetCore.Mvc.Internal;
    public class MonitorController : Controller
    {
        readonly IActionDescriptorCollectionProvider provider;
        public MonitorController(IActionDescriptorCollectionProvider provider)
        {
            this.provider = provider;
        }

        [Route("{*url}")]
        [ActionName("Index")]
        public IActionResult Index([FromRoute]string url)
        {
            Console.WriteLine("MonitorController Index called.");
            IEnumerable<ActionDescriptor> openRoutes = this.provider.ActionDescriptors.Items
               .Where(
                   x => x.FilterDescriptors.All(f => f.Filter.GetType() != typeof(AuthorizeFilter)) ||
                       x.FilterDescriptors.Any(f => f.Filter.GetType() == typeof(AllowAnonymousFilter)));
            var openRoutesDisplay = openRoutes
               .Select(x => $"{x?.ActionConstraints?.OfType<HttpMethodActionConstraint>().FirstOrDefault()?.HttpMethods.First()} -> {x.AttributeRouteInfo?.Template}");
            var roleGroupedRoutesDisplay = this.provider.ActionDescriptors.Items
               .Except(openRoutes)
               .GroupBy(r => this.GetAuthorizationRole(r))
               .SelectMany(
                   g =>
                       g.Select(x => $"[{g.Key}] {x?.ActionConstraints?.OfType<HttpMethodActionConstraint>().FirstOrDefault()?.HttpMethods.First()} -> {x.AttributeRouteInfo?.Template}")
               ).ToArray();
            var definedRoutes = openRoutesDisplay
               .Concat(new[] { "-------- SECURED ROUTES --------" })
               .Concat(roleGroupedRoutesDisplay);
            Console.WriteLine(string.Join(Environment.NewLine, definedRoutes));
            return this.Ok(definedRoutes);
        }

        public string GetAuthorizationRole(ActionDescriptor action)
        {
            var allowedRoles = ((RolesAuthorizationRequirement) action.FilterDescriptors.Where(x => x.Filter.GetType() == typeof(AuthorizeFilter))
                .SelectMany(x => ((AuthorizeFilter) x.Filter).Policy.Requirements)
                .FirstOrDefault(x => x.GetType() == typeof(RolesAuthorizationRequirement)))?.AllowedRoles;
            if (allowedRoles == null)
            {
                return "Authenticated";
            }
            return string.Join(", ", allowedRoles);
        }
    }
}
