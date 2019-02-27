package gd.example.springsecurity.sharedauth

import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.userdetails.UserDetails

class SafebitUser(private val name: String, private val roles: MutableCollection<GrantedAuthority>) : UserDetails {

    override fun getUsername(): String = name

    override fun getAuthorities(): MutableCollection<out GrantedAuthority> = roles

    override fun isEnabled(): Boolean = true

    override fun isCredentialsNonExpired(): Boolean = true

    override fun getPassword(): String = "N/A"

    override fun isAccountNonExpired(): Boolean = true

    override fun isAccountNonLocked(): Boolean = true
}