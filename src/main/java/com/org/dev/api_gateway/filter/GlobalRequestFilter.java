package com.org.dev.api_gateway.filter;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;


@Component
public class GlobalRequestFilter implements GlobalFilter, Ordered {


    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        System.out.println("GlobalFilter triggered for: " + exchange.getRequest().getPath());
        // Get the security context reactively
        return ReactiveSecurityContextHolder.getContext()
                .map(context -> {
                    OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) context.getAuthentication();
                    DefaultOidcUser user = (DefaultOidcUser) oauthToken.getPrincipal();
                    String accessToken = user.getIdToken().getTokenValue();
                    System.out.println("Access Token: " + accessToken);
                    System.out.println("Principal: " + oauthToken.getPrincipal().getAttributes());
                    return accessToken;
                })
                .flatMap(token -> {
                    if (token != null) {
                        // Modify the request headers to include the token
                        HttpHeaders headers = new HttpHeaders();
                        headers.putAll(exchange.getRequest().getHeaders());
                        headers.set(HttpHeaders.AUTHORIZATION, "Bearer " + token);

                        /*String sessionCookie = exchange.getRequest().getCookies()
                                .getFirst("SESSION")
                                .getValue();
                        headers.set("Cookie", "SESSION=" + sessionCookie);*/

                        // Create a mutated exchange with the new headers
                        ServerWebExchange mutatedExchange = exchange.mutate()
                                .request(exchange.getRequest().mutate().headers(h -> h.addAll(headers)).build())
                                .build();
                        return chain.filter(mutatedExchange);
                    }
                    // If no token, proceed without modification
                    return chain.filter(exchange);
                })
                .onErrorResume(e -> {
                    // Log the error and continue without token (or handle differently)
                    System.err.println("Error retrieving token: " + e.getMessage());
                    return chain.filter(exchange);
                });
    }

    @Override
    public int getOrder() {
        return -200; // Run before most built-in filters (e.g., NettyRoutingFilter)
    }
}
