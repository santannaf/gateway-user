package com.gateway.security.authenticate

import org.springframework.security.core.AuthenticationException
import org.springframework.security.web.server.WebFilterExchange
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler
import org.springframework.stereotype.Component
import reactor.core.publisher.Mono

@Component
class WebFilterChainServerAuthenticationFailedHandler : ServerAuthenticationFailureHandler {
    override fun onAuthenticationFailure(
        webFilterExchange: WebFilterExchange, exception: AuthenticationException
    ): Mono<Void> {
        val exchange = webFilterExchange.exchange
        return webFilterExchange.chain.filter(exchange)
    }
}