package gd.example.springsecurity.sharedauth

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication
open class SharedAuthApplication

fun main(args: Array<String>) {
    runApplication<SharedAuthApplication>(*args)
}

