package com.example.resourceserver.controller;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class Controller {



//    @GetMapping("/demo")
//    public String demo(){
//        return "demo";
//    }
    @GetMapping("/demo")
    public String demo(Authentication authentication){
        return authentication.getAuthorities().toString();
    }
}
