package com.gateway.security.token

import org.springframework.security.core.AuthenticationException

class InvalidBearerToken(message: String?) : AuthenticationException(message)