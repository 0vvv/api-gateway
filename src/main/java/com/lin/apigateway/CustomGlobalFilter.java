package com.lin.apigateway;


import com.lin.apiclientsdk.utils.SignUtils;
import com.lin.apicommon.model.entity.InterfaceInfo;
import com.lin.apicommon.model.entity.User;
import com.lin.apicommon.service.InnerInterfaceInfoService;
import com.lin.apicommon.service.InnerUserService;
import com.lin.apicommon.service.UserInterfaceInfoService;
import lombok.extern.slf4j.Slf4j;
import org.apache.dubbo.config.annotation.DubboReference;
import org.reactivestreams.Publisher;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.core.io.buffer.DefaultDataBufferFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.http.server.reactive.ServerHttpResponseDecorator;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Slf4j
@Component
public class CustomGlobalFilter implements GlobalFilter, Ordered {
    @DubboReference
    private InnerUserService innerUserService;

    @DubboReference
    private InnerInterfaceInfoService innerInterfaceInfoService;

    @DubboReference
    private UserInterfaceInfoService userInterfaceInfoService;

    private static final List<String> IP_WHITE_LIST = Arrays.asList("127.0.0.1");

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        // 打印请求日志
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getPath().value();
        String method = request.getMethod().toString();
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
        User user = null;
        try {
            user = innerUserService.getInvokeUser(accessKey, "test");
        } catch (Exception e) {
            log.error("getInvokeUser error", e);
        }
        if (user == null) {
            return handleNoAuth(response);
        }
        if (Long.parseLong(nonce) > 10000) {
            return handleNoAuth(response);
        }
        Long currentTime = System.currentTimeMillis() / 1000;
        final Long FIVE_MINITUES = 60 * 5L;
        if (currentTime - Long.parseLong(timestamp) >= FIVE_MINITUES) {
            return handleNoAuth(response);
        }
        // String secretKey = user.getSecretKey();  correct
        String secretKey = "abcdefg"; // wrong, 因为user类的问题先不改
        String serverSign = SignUtils.getSign(body, secretKey);
        if (!sign.equals(serverSign)) {
            return handleNoAuth(response);
        }
        // 判断请求的模拟接口是否存在
        InterfaceInfo interfaceInfo = innerInterfaceInfoService.getInterfaceInfo(path, method);
        if (interfaceInfo == null) {
            return handleNoAuth(response);
        }
        // 转发请求，调用模拟接口
        // Mono<Void> filter = chain.filter(exchange);
        return handleResponse(exchange, chain, interfaceInfo.getId(), user.getId()); // 确保按顺序执行，不被异步操作影响
        // 执行完上一步的接口再输出响应日志
    }

    public Mono<Void> handleResponse(ServerWebExchange exchange, GatewayFilterChain chain, long interfaceId, long userId) {
        try {
            ServerHttpResponse originalResponse = exchange.getResponse();
            // 缓存数据
            DataBufferFactory bufferFactory = originalResponse.bufferFactory();
            // 获取响应码
            HttpStatus statusCode = (HttpStatus) originalResponse.getStatusCode();
            if (statusCode != HttpStatus.OK) {
                return chain.filter(exchange); //降级处理返回数据
            }
            // 装饰response
            ServerHttpResponseDecorator decoratedResponse = new ServerHttpResponseDecorator(originalResponse) {
                @Override
                public Mono<Void> writeWith(Publisher<? extends DataBuffer> body) {
                    // writeWith往返回值里面写数据
                    if (body instanceof Flux) {
                        // body是一个Flux实例
                        Flux<? extends DataBuffer> fluxBody = Flux.from(body);
                        return super.writeWith(
                                fluxBody.buffer().map(dataBuffers -> {
                                    // 接口调用成功，接口调用次数+1
                                    try {
                                        userInterfaceInfoService.invokeCount(interfaceId, userId);
                                    } catch (Exception e) {
                                        log.error("invokeCount error", e);
                                    }
                                    // 合并多个流集合，解决返回体分段传输
                                    DataBufferFactory dataBufferFactory = new DefaultDataBufferFactory();
                                    DataBuffer buff = dataBufferFactory.join(dataBuffers);
                                    byte[] content = new byte[buff.readableByteCount()];
                                    buff.read(content);
                                    DataBufferUtils.release(buff);//释放掉内存
                                    MediaType contentType = originalResponse.getHeaders().getContentType();
                                    if (!MediaType.APPLICATION_JSON.isCompatibleWith(contentType)) {
                                        return bufferFactory.wrap(content);
                                    }
                                    // 构建返回日志
                                    String joinData = new String(content);
                                    log.info("响应结果" + joinData);
//                            if (response.getStatusCode() == HttpStatus.OK) {
//
//                            }
//                                    // 调用失败，返回一个规范的错误
//                            else {
//                                return handleInvokeError(response);
//                            }
                                    List<Object> rspArgs = new ArrayList<>();
                                    rspArgs.add(originalResponse.getStatusCode().value());
                                    rspArgs.add(exchange.getRequest().getURI());
                                    rspArgs.add(joinData);
                                    getDelegate().getHeaders().setContentLength(joinData.getBytes().length);
                                    return bufferFactory.wrap(joinData.getBytes());
                                }));
                    } else {
                        log.error("<-- {} 响应code异常", getStatusCode());
                    }
                    return super.writeWith(body);
                }
            };
            // 设置response对象为装饰后的对象
            return chain.filter(exchange.mutate().response(decoratedResponse).build());
        } catch (Exception e) {
            log.error("gateway log exception.\n" + e);
            return chain.filter(exchange);
        }
    }

    public Mono<Void> handleNoAuth(ServerHttpResponse response) {
        response.setStatusCode(HttpStatus.FORBIDDEN);
        return response.setComplete();
    }

    public Mono<Void> handleInvokeError(ServerHttpResponse response) {
        response.setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR);
        return response.setComplete();
    }

    @Override
    public int getOrder() {
        return -1;
    }

}