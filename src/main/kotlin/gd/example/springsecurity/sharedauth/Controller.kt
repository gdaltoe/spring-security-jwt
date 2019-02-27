package gd.example.springsecurity.sharedauth

import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController
import java.security.Principal

@RestController
open class Controller {

    @PreAuthorize("hasAnyRole('ROLE_ADMIN')")
    @GetMapping("hello")
    open fun hello(principal: Principal): String {
        return "Hello ${principal.name}!"
    }

    @PreAuthorize("hasAnyRole('ROLE_ADMIN','ROLE_USER')")
    @GetMapping("bye")
    open fun bye(principal: Principal): String {
        return "Bye ${principal.name}!"
    }

}