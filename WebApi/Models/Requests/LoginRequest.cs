using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace WebApi.Models.Requests
{
    public class LoginRequest
    {
        [EmailAddress]
        public string Email { get; set; }
        [PasswordPropertyText,MinLength(4)]
        public string Password { get; set; }
    }
}
