using AliaaCommon.Models;
using EasyMongoNet;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using MongoDB.Driver;
using Omu.ValueInjecter;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using TciDataLinks.Blazor.Server.Models;
using TciDataLinks.Blazor.Shared.Models;
using TciDataLinks.Blazor.Shared.ViewModels;

namespace TciDataLinks.Blazor.Server.Controllers
{
    [Route("api/[controller]/[action]")]
    [ApiController]
    public class AccountController : BaseController
    {
        public AccountController(IMongoCollection<AuthUserX> userCol) : base(userCol) { }

        [HttpPost]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        public async Task<ActionResult<ClientAuthUser>> Login(LoginVM model)
        {
            if (model == null)
                return Unauthorized();
            var user = userCol.CheckAuthentication(model.Username, model.Password);
            if (user != null)
            {
                var claims = new List<Claim>
                {
                    new Claim("Id", user.Id.ToString()),
                    new Claim(ClaimTypes.NameIdentifier, model.Username),
                    new Claim(ClaimTypes.Name, user.FirstName),
                    new Claim(ClaimTypes.Surname, user.LastName)
                };
                if (user.IsAdmin)
                    claims.Add(new Claim("IsAdmin", "true"));

                var perms = new StringBuilder();
                foreach (var perm in user.Permissions)
                    perms.Append(perm).Append(',');
                claims.Add(new Claim(nameof(Permission), perms.ToString()));

                var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                var principal = new ClaimsPrincipal(identity);
                await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);

                var clientUser = Mapper.Map<ClientAuthUser>(user);
                return clientUser;
            }
            return Unauthorized();
        }

        [Authorize]
        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme,
                new AuthenticationProperties { IsPersistent = false });
            return Ok();
        }

        [Authorize]
        [HttpPost]
        public async Task<IActionResult> ChangePassword(ChangePasswordVM model)
        {
            var user = userCol.FindFirst(u => u.Id == UserId);
            if (user != null)
            {
                if (AuthUserDBExtention.GetHash(model.CurrentPassword) == user.HashedPassword)
                {
                    if (model.NewPassword == model.RepeatNewPassword)
                    {
                        user.Password = model.NewPassword;
                        await userCol.InsertOneAsync(user);
                        return Ok();
                    }
                    else
                        return BadRequest("رمز جدید و تکرار آن باهم برابر نیستند.");
                }
                else
                    return BadRequest("رمز فعلی اشتباه میباشد.");
            }
            return Unauthorized();
        }

        [Authorize(nameof(Permission.ManageUsers))]
        [HttpPost]
        public async Task<IActionResult> Add(NewUserVM user)
        {
            if (!ModelState.IsValid)
                return BadRequest();

            if (await userCol.AnyAsync(u => u.Username == user.Username))
                return BadRequest(new Dictionary<string, List<string>> { { nameof(NewUserVM.Username), new List<string> { "نام کاربری قبلا موجود است!" } } });
            var authUser = Mapper.Map<AuthUserX>(user);
            await userCol.InsertOneAsync(authUser);
            return Ok();
        }

        [Authorize(nameof(Permission.ManageUsers))]
        public async Task<ActionResult<List<ClientAuthUser>>> List()
        {
            return (await userCol.Find(_ => true).SortBy(u => u.LastName).ThenBy(u => u.FirstName)
                .Project(Builders<AuthUserX>.Projection.Exclude(u => u.HashedPassword)).As<AuthUserX>()
                .ToCursorAsync()).ToEnumerable().Select(u => Mapper.Map<ClientAuthUser>(u)).ToList();
        }

        [Authorize(nameof(Permission.ManageUsers))]
        [HttpPost]
        public async Task<IActionResult> Save(ClientAuthUser user)
        {
            if (!ModelState.IsValid)
                return BadRequest("اطلاعات کاربری نامعتبر است!");
            var existing = await userCol.FindByIdAsync(user.Id);
            if (existing == null)
                return BadRequest("کاربر یافت نشد!");
            existing.InjectFrom(user);
            await userCol.ReplaceOneAsync(u => u.Id == user.Id, existing);
            return Ok();
        }
    }
}
