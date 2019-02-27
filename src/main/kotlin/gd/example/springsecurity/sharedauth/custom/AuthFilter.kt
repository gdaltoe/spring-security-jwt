package gd.example.springsecurity.sharedauth.custom

import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.web.filter.OncePerRequestFilter
import javax.servlet.FilterChain
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse


class AuthFilter : OncePerRequestFilter() {
    override fun doFilterInternal(request: HttpServletRequest, response: HttpServletResponse, filterChain: FilterChain) {
        val userId = request?.getHeader("X-Auth-Username") ?: ""
        val iban = request?.getHeader("X-Auth-Password") ?: ""

        val authentication = HeaderAuthenticationToken(userId, iban, mutableListOf(SimpleGrantedAuthority("ROLE_USER")))
        SecurityContextHolder.getContext().authentication = authentication
        filterChain.doFilter(request, response);
    }
}