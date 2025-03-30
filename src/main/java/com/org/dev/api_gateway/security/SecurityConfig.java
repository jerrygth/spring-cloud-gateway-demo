package com.org.dev.api_gateway.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationSuccessHandler;
import reactor.core.publisher.Mono;
import org.springframework.security.web.server.WebFilterExchange;

import java.net.URI;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig  {
    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) throws Exception {
        http
                .authorizeExchange((authorize) ->
                        authorize.pathMatchers("/login/**","/oauth2/**").permitAll()
                        .anyExchange().authenticated()

                )
                .oauth2Login(oauth2 -> oauth2
                        .authenticationSuccessHandler(new RedirectServerAuthenticationSuccessHandler() {
                            @Override
                            public Mono<Void> onAuthenticationSuccess(WebFilterExchange webFilterExchange, Authentication authentication) {
                                System.out.println("Success handler triggered for: " + authentication.getName());
                                webFilterExchange.getExchange().getResponse().setStatusCode(HttpStatus.FOUND);
                                webFilterExchange.getExchange().getResponse().getHeaders().setLocation(URI.create("/login/welcome"));
                                return Mono.empty();
                            }
                        }))
                .csrf(ServerHttpSecurity.CsrfSpec::disable);
        return http.build();
    }
}

