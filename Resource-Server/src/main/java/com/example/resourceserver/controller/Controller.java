package com.example.resourceserver.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collection;

@RestController
public class Controller {



//    @GetMapping("/demo")
//    public String demo(){
//        return "demo";
//    }
    @GetMapping("/demo")
    public Collection<? extends GrantedAuthority> demo(Authentication authentication){
        return authentication.getAuthorities();
    }
}
