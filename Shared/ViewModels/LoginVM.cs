using System.ComponentModel.DataAnnotations;

namespace TciDataLinks.Blazor.Shared.ViewModels
{
    public class LoginVM
    {
        [Required(ErrorMessage = "نام کاربری اجباریست!")]
        [Display(Name = "نام کاربری")]
        public string Username { get; set; }

        [Required(ErrorMessage = "رمز عبور اجباریست!")]
        [Display(Name = "رمز عبور")]
        public string Password { get; set; }

        public bool RememberMe { get; set; }
    }
}
