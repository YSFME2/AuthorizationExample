namespace WebApi.Models.Responses
{
    public class ErrorResponse
    {
        public string Code { get; set; }
        public string Description { get; set; }
        public string? Field { get; set; }
    }
}
