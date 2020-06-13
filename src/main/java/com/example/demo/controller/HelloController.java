package com.example.demo.controller;

import com.alibaba.fastjson.JSONObject;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.core.web.reactive.function.OAuth2BodyExtractors;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import javax.annotation.Resource;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.util.*;

@RestController
public class HelloController {

    private String accessToken;

    @Resource
    private RestTemplate restTemplate;

    @RequestMapping("/auth")
    public Mono<Void> auth(ServerWebExchange exchange) {
        String client_id="0e2cae5e8c1498c4276b113355c815b265428e68a189bd75025e1bd7e9e4bbc1";
        String redirect_uri="http://localhost:8080/login/gitee";
        String response_type="code";

        String url="https://gitee.com/oauth/authorize?response_type="+response_type+
                "&client_id="+client_id+"&scope=user_info"+
                "&redirect_uri="+ URLEncoder.encode(redirect_uri, Charset.defaultCharset());

        return Mono.fromRunnable(()->{
            ServerHttpResponse response=exchange.getResponse();
            response.setStatusCode(HttpStatus.FOUND);
            response.getHeaders().setLocation(URI.create(url));
        });
    }

    @RequestMapping("/login/gitee2")
    public JSONObject redirect(ServerWebExchange exchange){
        Map<String,String> params=new HashMap<>();

        params.put("client_id","0e2cae5e8c1498c4276b113355c815b265428e68a189bd75025e1bd7e9e4bbc1");
        params.put("client_secret","a375bffedce8119c9ebba0a7896ed070e6406355f1c143f8a045c58cafc4b9ee");
        params.put("grant_type","authorization_code");
        params.put("redirect_uri","http://localhost:8080/login/gitee");
        params.put("code",exchange.getRequest().getQueryParams().getFirst("code"));
        //params.put("scope","user_info%20projects");

        HttpHeaders headers=new HttpHeaders();
        headers.add("User-Agent",exchange.getRequest().getHeaders().getFirst("User-Agent"));
        //headers.add("User-Agent","Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36");
        //headers.add("User-Agent",request.getHeader("User-Agent"));

        HttpEntity<Map<String,String>> entity=new HttpEntity<>(params,headers);
        String result=restTemplate.postForObject("https://gitee.com/oauth/token",entity,String.class);
        System.out.println(result);

        JSONObject object= JSONObject.parseObject(result);
        System.out.println("map："+object.getInnerMap());

        accessToken=object.getString("access_token");
        System.out.println("access_token："+object.getString("access_token"));

        System.out.println("refresh_token："+object.getString("refresh_token"));

        String scope=object.getString("scope");
        Set<String> scopes = new HashSet<>(Arrays.asList(scope.split(" ")));
        System.out.println(scopes);

        System.out.println("scope："+object.getString("scope"));
        System.out.println("created_at："+object.getString("created_at"));
        System.out.println("token_type："+object.getString("token_type"));
        System.out.println("expires_in："+object.getString("expires_in"));

        return object;
    }

    @RequestMapping("/login/gitee")
    public Mono<OAuth2AccessTokenResponse> redirect2(ServerWebExchange exchange){
        Map<String,String> params=new HashMap<>();

        params.put("client_id","0e2cae5e8c1498c4276b113355c815b265428e68a189bd75025e1bd7e9e4bbc1");
        params.put("client_secret","a375bffedce8119c9ebba0a7896ed070e6406355f1c143f8a045c58cafc4b9ee");
        params.put("grant_type","authorization_code");
        params.put("redirect_uri","http://localhost:8080/login/gitee");
        params.put("code",exchange.getRequest().getQueryParams().getFirst("code"));
        //params.put("scope","user_info%20projects");

        return Mono.defer(() -> WebClient.create().post().uri("https://gitee.com/oauth/token",new Object[0])
                .headers(headers -> headers.add("User-Agent",exchange.getRequest().getHeaders().getFirst("User-Agent")))
                .body(BodyInserters.fromFormData("grant_type","authorization_code")
                        .with("client_id","0e2cae5e8c1498c4276b113355c815b265428e68a189bd75025e1bd7e9e4bbc1")
                        .with("client_secret","a375bffedce8119c9ebba0a7896ed070e6406355f1c143f8a045c58cafc4b9ee")
                        .with("redirect_uri","http://localhost:8080/login/gitee")
                        .with("code", Objects.requireNonNull(exchange.getRequest().getQueryParams().getFirst("code"))))
                .exchange().flatMap(response -> response.body(OAuth2BodyExtractors.oauth2AccessTokenResponse()))
                .doOnSuccess(oAuth2AccessTokenResponse -> accessToken=oAuth2AccessTokenResponse.getAccessToken().getTokenValue())
        );
    }

    @RequestMapping("/getUser")
    public String getUser(ServerWebExchange exchange) {
        Map<String,String> params=new HashMap<>();
        params.put("access_token",accessToken);

        HttpHeaders httpHeaders=new HttpHeaders();
        System.out.println("User-Agent："+exchange.getRequest().getHeaders().getFirst("User-Agent"));
        httpHeaders.add("User-Agent","Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36");
        //httpHeaders.add("User-Agent",request.getHeader("User-Agent"));

        HttpEntity<Object> entity=new HttpEntity<>(httpHeaders);

        return restTemplate.exchange("https://gitee.com/api/v5/user?access_token={access_token}", HttpMethod.GET,entity,String.class,params).getBody();
    }

    @RequestMapping("/getUser2")
    public Mono<OAuth2User> getUser2(ServerWebExchange exchange) {
        ParameterizedTypeReference<Map<String,Object>> parameterizedTypeReference= new ParameterizedTypeReference<>() {};

        Mono<Map<String, Object>> userAttributes =WebClient.create().get().uri("https://gitee.com/api/v5/user",new Object[0])
                .headers(headers ->{
                    headers.add("User-Agent",exchange.getRequest().getHeaders().getFirst("User-Agent"));
                    headers.setBearerAuth(accessToken);
                }).retrieve().bodyToMono(parameterizedTypeReference);

        return userAttributes.map(attrs ->{
            Set<GrantedAuthority> authorities=new HashSet<>();
            authorities.add(new SimpleGrantedAuthority("ROLE_USER"));

            return new DefaultOAuth2User(authorities,attrs,"name");
        });
    }
}
