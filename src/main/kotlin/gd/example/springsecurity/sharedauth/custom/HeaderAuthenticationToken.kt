package gd.example.springsecurity.sharedauth.custom

import org.springframework.security.authentication.AbstractAuthenticationToken
import org.springframework.security.core.GrantedAuthority

class HeaderAuthenticationToken(
        val userId: String,
        val iban: String,
        authorities: MutableCollection<out GrantedAuthority>?) : AbstractAuthenticationToken(authorities) {

    override fun getCredentials(): Any {
        return iban
    }

    override fun getPrincipal(): Any {
        return userId
    }

}