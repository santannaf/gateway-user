package com.gateway.security.token

import org.springframework.security.authentication.AbstractAuthenticationToken
import org.springframework.security.core.authority.AuthorityUtils

class BearerToken(internal val value: String) : AbstractAuthenticationToken(AuthorityUtils.NO_AUTHORITIES) {
    override fun getCredentials(): Any = value
    override fun getPrincipal(): Any = value
}