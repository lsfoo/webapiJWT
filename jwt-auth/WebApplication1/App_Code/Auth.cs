using System.Net;
using System.Net.Http;
using System.Text;
using System.Web.Http;
using System.Web.Http.Controllers;
using System;
using jwt_auth.Models;

/// <summary>
/// 用户验证类
/// </summary>
public class Auth : AuthorizeAttribute
{

    AuthorizeResult result = new AuthorizeResult();
    /// <summary>
    /// 重写IsAuthorized 结合token类实现jwt+数据库验证
    /// </summary>
    /// <param name="context"></param>
    /// <returns></returns>
    protected override bool IsAuthorized(HttpActionContext context)
    {
        try
        {
            result.Token = context.Request.Headers.Authorization.ToString();

            //验证token
            Token jwt = new Token();
            int authCode = jwt.valid(result.Token);
            if (authCode == 200) { return true; }
            result.Code = authCode;

        }
        catch (Exception)
        {
            result.Code = 550;
            result.Message = "没有设置请求头部 Authorization 并把token值给他";
            return false;
        }
        result.Message = "不知道错误";
        return false;
    }
    /// <summary>
    ///  没有通过验证返回信息
    /// </summary>
    /// <param name="context"></param>
    protected override void HandleUnauthorizedRequest(HttpActionContext context)
    {
        base.HandleUnauthorizedRequest(context);
      //  var response = context.Response = context.Response ?? new HttpResponseMessage();
       // response.StatusCode = HttpStatusCode.Forbidden;
        //response.Content = new StringContent(Json.Encode(result), Encoding.UTF8, "text/json");
    }
}