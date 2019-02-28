package gd.example.springsecurity.sharedauth.preauth

import io.jsonwebtoken.Jwts
import org.springframework.beans.factory.annotation.Value
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken
import org.springframework.web.filter.OncePerRequestFilter
import java.nio.charset.Charset
import javax.servlet.FilterChain
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse


open class JwtTokenAuthFilter : JwtAuthFilter, OncePerRequestFilter() {

    @Value("\${jwt.token.headerName}")
    lateinit var jwtTokenHeaderName: String

    @Value("\${jwt.token.signing.key}")
    lateinit var jwtTokenSigningKey: String

    override fun doFilterInternal(request: HttpServletRequest, response: HttpServletResponse, chain: FilterChain) {
        val token = request.getHeader(jwtTokenHeaderName)
        if (token == null) {
            chain.doFilter(request, response)
            return
        }

        try {
            val claims = Jwts.parser()
                    .setSigningKey(jwtTokenSigningKey.toByteArray(Charset.forName("UTF-8")))
                    .parseClaimsJws(token)
                    .body

            val username = claims.subject
            if (username != null) {
                val auth = PreAuthenticatedAuthenticationToken(username, "N/A")
                SecurityContextHolder.getContext().authentication = auth
            }

        } catch (e: Exception) {
            SecurityContextHolder.clearContext()
        }

        chain.doFilter(request, response)
    }
}