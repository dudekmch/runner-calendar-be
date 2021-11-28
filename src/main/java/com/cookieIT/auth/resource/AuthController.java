package com.cookieIT.auth.resource;

import com.cookieIT.auth.jwt.model.UserCredentialAuthRequest;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("auth")
public class AuthController {

    @PostMapping("/register")
    public void register(@RequestBody UserCredentialAuthRequest request){
        System.out.println(request);
    }

    @PostMapping("/test")
    public void test(@RequestBody UserCredentialAuthRequest request){
        System.out.println("Test" + request);
    }
}
