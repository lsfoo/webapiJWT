using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace jwt_auth.Models
{
    public class AuthorizeResult
    {
        public string Message { get; set; }
        public int Code { get; set; }
        public string Token { get; set; }
    }
}