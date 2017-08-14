using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;
using jwt_auth.App_Code;

namespace jwt_auth.Controllers
{
    public class HomeController : ApiController
    {
        [Route("home")]
        [JwtAuth]
        public string Get()
        {
            return "通过验证";
        }
        [Route("token")]
        public IHttpActionResult GetToken()
        {
            var tk = new Token().Make(123).ToString();
            return Json<dynamic>(new { access_token = tk });
        }
    }
}
