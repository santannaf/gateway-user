package com.gateway.security.filter

import com.gateway.security.token.BearerToken
import com.gateway.security.token.InvalidBearerToken
import com.gateway.security.token.JwtSupport
import com.nimbusds.jose.JWEObject
import com.nimbusds.jose.crypto.DirectDecrypter
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jwt.SignedJWT
import kotlinx.coroutines.reactor.awaitSingleOrNull
import kotlinx.coroutines.reactor.mono
import org.slf4j.LoggerFactory
import org.springframework.security.access.AccessDeniedException
import org.springframework.security.authentication.ReactiveAuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.AuthorityUtils
import org.springframework.security.core.userdetails.ReactiveUserDetailsService
import org.springframework.stereotype.Component
import reactor.core.publisher.Mono

@Component
class ReactiveAuthenticateFilterManager(
    private val jwtSupport: JwtSupport,
    private val users: ReactiveUserDetailsService
) : ReactiveAuthenticationManager {
    private val log = LoggerFactory.getLogger(javaClass)

    override fun authenticate(authentication: Authentication?): Mono<Authentication> {
        return Mono.justOrEmpty(authentication)
            .filter { auth -> auth is BearerToken }
            .cast(BearerToken::class.java)
            .flatMap { jwt -> mono { validateTokenSignature(jwt) } }
            .onErrorMap { error -> InvalidBearerToken(error.message) }
    }

    fun decryptToken(encryptedToken: String): String {
        log.info("Decrypting token")
        val jweObject = JWEObject.parse(encryptedToken)
        val directDecrypter = DirectDecrypter("qxBEEQv7E8aviX1KUcdOiF5ve5COUPAr".toByteArray())
        jweObject.decrypt(directDecrypter)
        log.info("Token decrypted, returning signed token . . . ")
        return jweObject.payload.toSignedJWT().serialize()
    }


    private suspend fun validateTokenSignature(bearerToken: BearerToken): Authentication {
        log.info("Starting method to validate token signature...")
        val token = decryptToken(bearerToken.value)
        val signedJWT = SignedJWT.parse(token)
        log.info("Token Parsed! Retrieving public key from signed token")
        val publicKey = RSAKey.parse(signedJWT.header.jwk.toJSONObject())
        log.info("Public key retrieved, validating signature. . . ")
        if (!signedJWT.verify(RSASSAVerifier(publicKey))) throw AccessDeniedException("Invalid token signature!")
        log.info("The token has a valid signature")

        val r: String = signedJWT.jwtClaimsSet.toJSONObject().getAsString("authorities")
        return UsernamePasswordAuthenticationToken(signedJWT.jwtClaimsSet.subject, null, AuthorityUtils.createAuthorityList(r))
    }

    private suspend fun validate(token: BearerToken): Authentication {
        token.value
        val username = jwtSupport.getUsername(token)
        val user = users.findByUsername(username).awaitSingleOrNull()

        if (jwtSupport.isValid(token, user)) {
            return UsernamePasswordAuthenticationToken(user?.username, user?.password, user?.authorities)
        }

        throw IllegalArgumentException("Token is not valid.")
    }
}