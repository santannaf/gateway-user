package com.gateway.security

import com.gateway.repository.UsersRepository
import org.springframework.security.core.userdetails.ReactiveUserDetailsService
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.stereotype.Component
import reactor.core.publisher.Mono

@Component
class UserDetailsServiceImpl(
    private val repository: UsersRepository
) : ReactiveUserDetailsService {
    override fun findByUsername(username: String): Mono<UserDetails> {
        return repository.findByUsername(username)
            .map(::UserDetailsImpl)
    }
}