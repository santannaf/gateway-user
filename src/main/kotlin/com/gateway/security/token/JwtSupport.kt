package com.gateway.security.token

import com.gateway.security.UserDetailsImpl
import com.nimbusds.jose.*
import com.nimbusds.jose.crypto.DirectEncrypter
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.security.Keys
import org.slf4j.LoggerFactory
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.stereotype.Component
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPublicKey
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.*
import java.util.stream.Collectors
import javax.crypto.SecretKey

@Component
class JwtSupport {
    private val log = LoggerFactory.getLogger(javaClass)
    private val key: SecretKey = Keys.hmacShaKeyFor("tNO+KhVrTj3B4q0+SEwz/NSvZq7y577jOjvY4uPgAR4=".toByteArray())
    private val parser = Jwts.parserBuilder().setSigningKey(key).build()

    fun createSignedJWT(auth: UserDetails): SignedJWT? {
        log.info("Starting to create the signed JWT")
        val applicationUser = auth as UserDetailsImpl

        val jwtClaimSet: JWTClaimsSet = createJWTClaimSet(applicationUser)
        val rsaKeys: KeyPair = generateKeyPair()

        log.info("Building JWK from the RSA Keys")
        val jwk: JWK = RSAKey.Builder(rsaKeys.public as RSAPublicKey).keyID(UUID.randomUUID().toString()).build()
        val signedJWT = SignedJWT(
            JWSHeader.Builder(JWSAlgorithm.RS256)
                .jwk(jwk)
                .type(JOSEObjectType.JWT)
                .build(), jwtClaimSet
        )
        log.info("Signing the token with the private RSA Key")
        val signer = RSASSASigner(rsaKeys.private)
        signedJWT.sign(signer)
        log.info("Serialized token '{}'", signedJWT.serialize())
        return signedJWT
    }

    private fun generateKeyPair(): KeyPair {
        log.info("Generating RSA 2048 bits Keys")
        val generator = KeyPairGenerator.getInstance("RSA")
        generator.initialize(2048)
        return generator.genKeyPair()
    }

    private fun createJWTClaimSet(applicationUser: UserDetailsImpl): JWTClaimsSet {
        log.info("Creating the JwtClaimSet Object for '{}'", applicationUser)
        return JWTClaimsSet.Builder()
            .subject(applicationUser.username)
            .claim("authorities", applicationUser.authorities
                .stream()
                .map { obj: GrantedAuthority -> obj.authority }
                .collect(Collectors.toList()))
            .issuer("http://academy.devdojo")
            .issueTime(Date())
            .expirationTime(Date(System.currentTimeMillis() + 10 * 1000L))
            .build()
    }

    fun encryptToken(signedJWT: SignedJWT?): String {
        log.info("Starting the encryptToken method")
        val directEncrypter = DirectEncrypter("qxBEEQv7E8aviX1KUcdOiF5ve5COUPAr".toByteArray())
        val jweObject = JWEObject(
            JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A128CBC_HS256)
                .contentType("JWT")
                .build(), Payload(signedJWT)
        )
        log.info("Encrypting token with system's private key")
        jweObject.encrypt(directEncrypter)
        log.info("Token encrypted")
        return jweObject.serialize()
    }

    fun generate(username: String): BearerToken {
        val builder = Jwts.builder()
            .setSubject(username)
            .setIssuedAt(Date.from(Instant.now()))
            .setExpiration(Date.from(Instant.now().plus(15, ChronoUnit.MINUTES)))
            .signWith(key)

        return BearerToken(builder.compact())
    }

    fun getUsername(token: BearerToken): String {
        return parser.parseClaimsJws(token.value).body.subject
    }

    fun isValid(token: BearerToken, user: UserDetails?): Boolean {
        val claims = parser.parseClaimsJws(token.value).body
        val unexpired = claims.expiration.after(Date.from(Instant.now()))

        return unexpired && (claims.subject == user?.username)
    }
}