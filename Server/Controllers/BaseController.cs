using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using MongoDB.Driver;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using TciDataLinks.Blazor.Server.Models;
using TciDataLinks.Blazor.Shared.Models;
using EasyMongoNet;

namespace TciDataLinks.Blazor.Server.Controllers
{
    public class BaseController : ControllerBase
    {
        protected readonly IMongoCollection<AuthUserX> userCol;

        public BaseController(IMongoCollection<AuthUserX> userCol)
        {
            this.userCol = userCol;
        }

        protected string Username => HttpContext.User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier)?.Value;

        protected string UserId => HttpContext.User.Claims.FirstOrDefault(c => c.Type == "Id")?.Value;

        protected IEnumerable<Permission> UserPermissions
        {
            get
            {
                if (User == null)
                    return Enumerable.Empty<Permission>();
                Claim claim = User.Claims.FirstOrDefault(c => c.Type == nameof(Permission));
                if (claim == null)
                    return Enumerable.Empty<Permission>();
                return claim.Value.Split(',', StringSplitOptions.RemoveEmptyEntries).Select(c => (Permission)Enum.Parse(typeof(Permission), c));
            }
        }

        protected AuthUserX GetUser()
        {
            var id = UserId;
            if (id != null)
                return userCol.FindById(id);
            return null;
        }
    }
}
