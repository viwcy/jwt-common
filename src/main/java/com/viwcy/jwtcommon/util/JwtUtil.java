package com.viwcy.jwtcommon.util;

import com.alibaba.fastjson.JSONObject;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.time.FastDateFormat;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.util.Date;
import java.util.Map;

/**
 * TODO //jwt工具模板
 *
 * <p> Title: JwtTemplate </p>
 * <p> Description: JwtTemplate </p>
 * <p> History: 2020/9/4 23:02 </p>
 * <pre>
 *      Copyright: Create by FQ, ltd. Copyright(©) 2020.
 * </pre>
 * Author  FQ
 * Version 0.0.1.RELEASE
 */
//@ConfigurationProperties(prefix = "jwt.config")
@Component
public class JwtUtil {

    /**
     * 时间模板，线程安全
     */
    private static final FastDateFormat FAST_DATE_FORMAT = FastDateFormat.getInstance("yyyy-MM-dd HH:mm:ss");

    /**
     * 头部认证名称
     */
    private static final String JWT_HEADER = "Authorization";

    /**
     * JWT头部标识
     */
    private static final String JWT_HEADER_TYPE = "JWT";

    /**
     * 前缀
     */
    private static final String JWT_PREFIX = "Bearer";

    /**
     * 签名秘钥
     */
    private static final String JWT_SECRET = "viwcy4611";

    @Autowired
    private HttpServletRequest request;

    /**
     * @param map
     * @return com.alibaba.fastjson.JSONObject
     * @Description TODO    根据身份ID标识，生成Token。jwtSecret:密钥，jwtExpire:过期时间
     * @Param subject
     * @Param jwtExpire
     * @date 2020/9/3 17:39
     * @author Fuqiang
     */
    public JSONObject createJwt(Map<String, Object> map, String subject, long jwtExpire) {
        Date now = new Date();
        Date expireDate = new Date(now.getTime() + jwtExpire * 60 * 1000L);
        String jwt = Jwts.builder()
                .claim("userInfo", map)
//                .claim("id", map.get("id"))
//                .claim("nickname", map.get("nickname"))
//                .claim("phone", map.get("phone"))
//                .claim("email", map.get("email"))
                .setHeaderParam("typ", JWT_HEADER_TYPE)//类型
                .setSubject(subject)//代表这个JWT的主体，相当于唯一标识
                .setIssuedAt(now)//是一个时间戳，代表这个JWT的签发时间
                .setExpiration(expireDate)//过期时间
                .signWith(SignatureAlgorithm.HS256, JWT_SECRET)//签名
                .setNotBefore(now)//是一个时间戳，代表这个JWT生效的开始时间，意味着在这个时间之前验证JWT是会失败的
                .compact();
        //构造返回值
        JSONObject json = new JSONObject();
        json.put("token", JWT_PREFIX + " " + jwt);
        json.put("token-type", JWT_HEADER_TYPE);
        json.put("token-header", JWT_HEADER);
        json.put("expire-time", FAST_DATE_FORMAT.format(expireDate));
        return json;
    }

    /**
     * @param jwt
     * @return io.jsonwebtoken.Claims
     * @Description TODO    解析jwt
     * @date 2020/9/3 17:40
     * @author Fuqiang
     */
    public Claims parsingJwt(String jwt) {
        return Jwts.parser().setSigningKey(JWT_SECRET).parseClaimsJws(jwt.replace(JWT_PREFIX + " ", "")).getBody();
    }

    /**
     * @param
     * @return com.fuqiang.userserver.model.UserEntity
     * @Description TODO    请求头获取jwt，解析登录用户ID
     * @date 2020/9/2 16:31
     * @author Fuqiang
     */
    public String getUserId() {
        String jwt = request.getHeader("Authorization");
        return StringUtils.isBlank(jwt) ? null : this.parsingJwt(jwt).getSubject();
    }

    public Map<String, Object> getUserInfo() {
        String jwt = request.getHeader("Authorization");
        try {
            return this.parsingJwt(jwt).get("userInfo", Map.class);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

}
