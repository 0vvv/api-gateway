package com.lin.apigateway;


import com.lin.apiclientsdk.utils.SignUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Arrays;
import java.util.List;

@Slf4j
@Component
public class CustomGlobalFilter implements GlobalFilter, Ordered {
    private static final List<String> IP_WHITE_LIST = Arrays.asList("127.0.0.1");

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        // 打印请求日志
        ServerHttpRequest request = exchange.getRequest();
        log.info("请求唯一标识：{}", request.getId());
        log.info("请求路径：{}", request.getPath().value());
        log.info("请求方法：{}", request.getMethod());
        log.info("请求参数：{}", request.getQueryParams());
        String sourceIP = request.getLocalAddress().getHostString();
        log.info("请求来源地址：{}", sourceIP);
        ServerHttpResponse response = exchange.getResponse();
        // 黑白名单
        if (!IP_WHITE_LIST.contains(sourceIP)) {
            log.error("非法请求，拒绝访问！");
            response.setStatusCode(HttpStatus.FORBIDDEN);
            return response.setComplete();
        }
        // 用户鉴权
        HttpHeaders headers = request.getHeaders();
        String accessKey = headers.getFirst("accessKey");
        String nonce = headers.getFirst("nonce");
        String timestamp = headers.getFirst("timestamp");
        String sign = headers.getFirst("sign");
        String body = headers.getFirst("body");
        if (!accessKey.equals("lin")) {
            return handleNoAuth(response);
        }
        if (Long.parseLong(nonce) > 10000) {
            return handleNoAuth(response);
        }
        Long currentTime = System.currentTimeMillis() / 1000;
        Long FIVE_MINITUES = 60 * 5L;
        if (currentTime - Long.parseLong(timestamp) >= FIVE_MINITUES) {
            return handleNoAuth(response);
        }
        String serverSign = SignUtils.getSign(body, "abcdefg");
        if (!sign.equals(serverSign)) {
            return handleNoAuth(response);
        }
        // 判断请求的模拟接口是否存在，从数据库中查询（但是该项目没有涉及到数据库的方法，这步骤不适合放在网关项目）

        return chain.filter(exchange);
    }

    public Mono<Void> handleNoAuth(ServerHttpResponse response) {
        response.setStatusCode(HttpStatus.FORBIDDEN);
        return response.setComplete();
    }

    @Override
    public int getOrder() {
        return -1;
    }

}