using Microsoft.EntityFrameworkCore;

namespace WebApi.Models
{
    [Owned]
    public class RefreshToken
    {
        public string Token { get; set; }
        public DateTime ExpireOn { get; set; }
        public DateTime CreatedOn { get; set; }
        public DateTime? RevokedOn { get; set; }
        public bool IsExpired => ExpireOn < DateTime.Now;
        public bool IsActive => RevokedOn == null && !IsExpired;
    }
}
