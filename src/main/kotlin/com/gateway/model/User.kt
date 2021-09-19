package com.gateway.model

import com.fasterxml.jackson.annotation.JsonProperty
import org.springframework.data.annotation.Id
import org.springframework.data.relational.core.mapping.Table

@Table("users")
data class User(
    @Id
    val id: Long,
    val username: String,
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    var password: String
)