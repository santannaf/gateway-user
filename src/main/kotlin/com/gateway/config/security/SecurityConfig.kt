package com.gateway.config.security

import com.gateway.security.authenticate.WebFilterChainServerAuthenticationFailedHandler
import com.gateway.security.converter.JwtServerAuthenticationConverter
import com.gateway.security.filter.ReactiveAuthenticateFilterManager
import org.springframework.context.annotation.Bean
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpMethod
import org.springframework.http.HttpStatus
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.web.server.SecurityWebFiltersOrder
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.web.reactive.result.view.CsrfRequestDataValueProcessor
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.security.web.server.authentication.AuthenticationWebFilter
import org.springframework.security.web.server.csrf.CookieServerCsrfTokenRepository
import org.springframework.security.web.server.csrf.CsrfToken
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono

@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
class SecurityConfig {
    @Bean
    fun passwordEncoder(): PasswordEncoder = BCryptPasswordEncoder()

    @Bean
    fun springSecurityFilterChain(
        converter: JwtServerAuthenticationConverter,
        http: ServerHttpSecurity,
        authManager: ReactiveAuthenticateFilterManager
    ): SecurityWebFilterChain {

        val filter = AuthenticationWebFilter(authManager)
        filter.setServerAuthenticationConverter(converter)
        filter.setAuthenticationFailureHandler(WebFilterChainServerAuthenticationFailedHandler())
        filter.setAuthenticationSuccessHandler(com.gateway.security.authenticate.WebFilterChainServerAuthenticationSuccessHandler())

        return http
            .exceptionHandling()
            .authenticationEntryPoint { exchange, _ ->
                Mono.fromRunnable {
                    exchange.response.statusCode = HttpStatus.UNAUTHORIZED
                    exchange.response.headers.set(HttpHeaders.WWW_AUTHENTICATE, "Bearer")
                }
            }
            .and()
            .authorizeExchange()
            .pathMatchers(HttpMethod.POST, "/login").permitAll()
            .anyExchange().authenticated()
            .and()
            .addFilterAt(filter, SecurityWebFiltersOrder.AUTHENTICATION)
            .httpBasic().disable()
            .formLogin().disable()
            .csrf().disable()
            .build()
            //.csrfTokenRepository(CookieServerCsrfTokenRepository.withHttpOnlyFalse())
    }

    fun csrfToken(exchange: ServerWebExchange): Mono<CsrfToken> {
        val csrfToken: Mono<CsrfToken> = exchange.getAttribute<Mono<CsrfToken>>(CsrfToken::class.java.name)!!
        return csrfToken.doOnSuccess { token: CsrfToken? ->
            exchange.attributes[CsrfRequestDataValueProcessor.DEFAULT_CSRF_ATTR_NAME] = token
        }
    }

//    private fun csrfTokenRepository(): ServerCsrfTokenRepository {
//        val repository = HttpSSessionCsrfTokenRepository()
//        repository.setSessionAttributeName("_csrf")
//        return repository
//    }
}