using System;
using System.Collections.Generic;
using JWT;
using System.Configuration;
using JWT.Algorithms;
using JWT.Serializers;
namespace jwt_auth.App_Code
{

    /// <summary>
    /// Token 的摘要说明
    /// </summary>
    public class Token
    {
        /// <summary>
        /// 加密串
        /// </summary>
        private string Secret { get; set; }
        /// <summary>
        /// token过期时间单位/秒
        /// </summary>
        private double TokenTimeOut { get; set; }
        public Token()
        {
            Secret = "GQDstcKs";
            TokenTimeOut = Convert.ToDouble(ConfigurationManager.AppSettings["tokenTimeOut"]);
        }
        public string Make(int key)
        {
            IDateTimeProvider provider = new UtcDateTimeProvider();
            var now = provider.GetNow();
            var unixEpoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc); // or use JwtValidator.UnixEpoch
            var secondsSinceEpoch = Math.Round((now - unixEpoch).TotalSeconds) + TokenTimeOut;
            var payload = new Dictionary<string, object>()
                         {
                             { "exp", secondsSinceEpoch },
                             { "key", key },
                         };
            IJwtAlgorithm algorithm = new HMACSHA256Algorithm();
            IJsonSerializer serializer = new JsonNetSerializer();
            IBase64UrlEncoder urlEncoder = new JwtBase64UrlEncoder();
            IJwtEncoder encoder = new JwtEncoder(algorithm, serializer, urlEncoder);
            return encoder.Encode(payload, Secret);
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="tokenString"></param>
        /// <returns>200通过,401token失效或者无效，402数据库无数据，其它设备登陆</returns>
        public int valid(string tokenString)
        {
            IJsonSerializer serializer = new JsonNetSerializer();
            IDateTimeProvider provider = new UtcDateTimeProvider();
            IJwtValidator validator = new JwtValidator(serializer, provider);
            IBase64UrlEncoder urlEncoder = new JwtBase64UrlEncoder();
            try
            {
                IJwtDecoder decoder = new JwtDecoder(serializer, validator, urlEncoder);
                // var json = decoder.Decode(tokenString, Secret, verify: true);
                var payload = decoder.DecodeToObject<IDictionary<string, object>>(tokenString, Secret, verify: true);
                return 1;
            }
            catch (System.Exception)
            {
                //   throw;
                //失效或者过期或者不合法
                return 401;
            }
        }
        public string RefreshToken(string tokenString)
        {
            IJsonSerializer serializer = new JsonNetSerializer();
            IDateTimeProvider provider = new UtcDateTimeProvider();
            IJwtValidator validator = new JwtValidator(serializer, provider);
            IBase64UrlEncoder urlEncoder = new JwtBase64UrlEncoder();
            try
            {
                IJwtDecoder decoder = new JwtDecoder(serializer, validator, urlEncoder);
                // var json = decoder.Decode(tokenString, Secret, verify: true);
                var payload = decoder.DecodeToObject<IDictionary<string, object>>(tokenString, Secret, verify: true);
                return "ok";
            }
            catch (System.Exception)
            {
                //失效或者过期或者不合法
                return "401";
            }

        }
    }
}