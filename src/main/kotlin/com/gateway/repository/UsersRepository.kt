package com.gateway.repository

import com.gateway.model.User
import org.springframework.data.repository.reactive.ReactiveCrudRepository
import reactor.core.publisher.Mono

interface UsersRepository : ReactiveCrudRepository<User, Long> {
    fun findByUsername(username: String): Mono<User>
}