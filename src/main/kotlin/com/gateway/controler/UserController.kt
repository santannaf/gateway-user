package com.gateway.controler

import com.gateway.model.User
import com.gateway.repository.UsersRepository
import com.gateway.security.token.JwtSupport
import kotlinx.coroutines.reactor.awaitSingleOrNull
import org.springframework.http.HttpStatus
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.security.core.userdetails.ReactiveUserDetailsService
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.server.ResponseStatusException
import reactor.core.publisher.Flux
import reactor.core.publisher.Mono
import java.security.Principal

data class Jwt(val token: String)
data class Profile(val username: String)

@RestController
class UserController(
    private val jwtSupport: JwtSupport,
    private val repository: UsersRepository,
    private val encoder: PasswordEncoder,
    private val users: ReactiveUserDetailsService
) {

    @GetMapping("/me")
    suspend fun me(@AuthenticationPrincipal principal: Principal): Profile {
        return Profile(principal.name)
    }

    @PostMapping("/login")
    suspend fun login(@RequestBody login: User): Jwt {
        val user = users.findByUsername(login.username).awaitSingleOrNull()

        user?.let {
            if (encoder.matches(login.password, it.password)) {
                val token = jwtSupport.createSignedJWT(it)
                return Jwt(jwtSupport.encryptToken(token))
            }
        }

        throw ResponseStatusException(HttpStatus.UNAUTHORIZED)
    }

    @PostMapping("/users")
    fun user(@RequestBody user: User): Mono<User> {
        with(user) {
            password = encoder.encode(user.password)
        }
        return repository.save(user)
    }

    @GetMapping("/users")
    fun users(): Flux<User> {
        return repository.findAll()
    }
}