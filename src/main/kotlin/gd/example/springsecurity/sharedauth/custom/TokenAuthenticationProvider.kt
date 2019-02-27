package gd.example.springsecurity.sharedauth.custom

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.core.Authentication
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.stereotype.Component

//@Component
class TokenAuthenticationProvider : AuthenticationProvider {

    @Autowired
    lateinit var userDetailsService: UserDetailsService

    override fun authenticate(authentication: Authentication?): Authentication {
        authentication ?: throw BadCredentialsException("Credentials not provided")
        if (userDetailsService.loadUserByUsername(authentication.principal as String).password == authentication.credentials) {
            authentication.isAuthenticated = true
            return authentication
        }
        throw BadCredentialsException("Credentials not correct")
    }

    override fun supports(p0: Class<*>?): Boolean {
        return p0?.isAssignableFrom(HeaderAuthenticationToken::class.java) ?: false
    }
}