using System.Net;
using System.Net.Http;
using System.Text;
using System.Web.Http;
using System.Web.Http.Controllers;
using System;
using jwt_auth.Models;

namespace jwt_auth.App_Code
{
    public class JwtAuth: AuthorizeAttribute
    {

        AuthorizeResult Result = new AuthorizeResult();
        protected override bool IsAuthorized(HttpActionContext context)
        {
            try
            {
                Result.Token = context.Request.Headers.Authorization.ToString();

                //验证token
                Token jwt = new Token();
                int authCode = jwt.valid(Result.Token);
                if (authCode == 200) { return true; }
                Result.Code = authCode;

            }
            catch (Exception)
            {
                Result.Code = 550;
                Result.Message = "没有设置请求头部 Authorization 并把token值给他";
                return false;
            }
            Result.Message = "不知道错误";
            return false;
        }
        protected override void HandleUnauthorizedRequest(HttpActionContext context)
        {
            base.HandleUnauthorizedRequest(context);
            var response = context.Response = context.Response ?? new HttpResponseMessage();
            response.StatusCode = HttpStatusCode.Forbidden;
            response.Content = new StringContent(Result.ToString());
        }
    }
}