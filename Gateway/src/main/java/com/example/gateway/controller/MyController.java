package com.example.gateway.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MyController
{
    @GetMapping("/cao")
    public String cao(){
        return "cao";
    }
}
