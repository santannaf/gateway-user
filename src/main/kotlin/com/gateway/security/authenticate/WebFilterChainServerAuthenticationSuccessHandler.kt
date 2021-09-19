package com.gateway.security.authenticate

import org.springframework.security.core.Authentication
import org.springframework.security.web.server.WebFilterExchange
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler
import org.springframework.stereotype.Component
import reactor.core.publisher.Mono

@Component
class WebFilterChainServerAuthenticationSuccessHandler : ServerAuthenticationSuccessHandler {
    override fun onAuthenticationSuccess(
        webFilterExchange: WebFilterExchange, authentication: Authentication
    ): Mono<Void> {
        val exchange = webFilterExchange.exchange
        return webFilterExchange.chain.filter(exchange)
    }
}