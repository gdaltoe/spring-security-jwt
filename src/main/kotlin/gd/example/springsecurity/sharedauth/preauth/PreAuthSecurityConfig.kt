package gd.example.springsecurity.sharedauth.preauth

import gd.example.springsecurity.sharedauth.SafebitUser
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Profile
import org.springframework.core.annotation.Order
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken
import org.springframework.security.web.authentication.preauth.RequestHeaderAuthenticationFilter
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter
import javax.servlet.Filter

@EnableWebSecurity
@EnableGlobalMethodSecurity(
        prePostEnabled = true,
        securedEnabled = true,
        jsr250Enabled = true)
open class PreAuthSecurityConfig : WebSecurityConfigurerAdapter(false) {

    @Autowired
    lateinit var userDetailsService: UserDetailsService

    override fun configure(http: HttpSecurity) {
        http
                .csrf().disable()
                .exceptionHandling()
                .authenticationEntryPoint(Http403ForbiddenEntryPoint())
                .and()
                .authorizeRequests()
                .anyRequest()
                .authenticated()
                .and()
                .addFilterBefore(jwtPreAuthFilter(), BasicAuthenticationFilter::class.java)
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
    }

    override fun configure(auth: AuthenticationManagerBuilder?) {
        auth?.authenticationProvider(preAuthProvider())
    }

    @Bean
    open fun preAuthProvider(): AuthenticationProvider {
        val provider = PreAuthenticatedAuthenticationProvider()
        provider.setPreAuthenticatedUserDetailsService(preAuthDetailService())
        return provider
    }

    @Bean
    open fun preAuthDetailService(): AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> {
        return AuthenticationUserDetailsService {
            return@AuthenticationUserDetailsService userDetailsService.loadUserByUsername(it.principal as String)
        }
    }

//    @Profile("!jwt")
//    @Bean
//    fun plainHeaderPreAuthFilter(): Filter {
//        val filter = RequestHeaderAuthenticationFilter()
//        filter.setAuthenticationManager(authenticationManager())
//        filter.setPrincipalRequestHeader("X-Auth-Username")
//        filter.setExceptionIfHeaderMissing(false)
//        return filter
//    }

    @Profile("jwt")
    @Bean
    fun jwtPreAuthFilter(): Filter {
        return JwtTokenAuthFilter()
    }

    @Profile("!generate-users")
    @Bean
    open fun preAuthUserDetailsService(): UserDetailsService {
        val user = SafebitUser("user", mutableListOf(SimpleGrantedAuthority("ROLE_USER")))
        val admin = SafebitUser("giorgio", mutableListOf(SimpleGrantedAuthority("ROLE_ADMIN")))
        val users = mutableListOf(user, admin)
        return UserDetailsService { username ->
            return@UserDetailsService users.firstOrNull { it.username == username }
                    ?: throw UsernameNotFoundException("User not found")
        }
    }

    @Profile("generate-users")
    @Bean
    open fun dummyUserDetailsService(): UserDetailsService {
        return UserDetailsService { username ->
            return@UserDetailsService SafebitUser(username, mutableListOf(SimpleGrantedAuthority("ROLE_USER")))
        }
    }

}
