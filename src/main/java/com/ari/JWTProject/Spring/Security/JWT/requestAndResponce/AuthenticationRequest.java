package com.ari.JWTProject.Spring.Security.JWT.requestAndResponce;

import lombok.Data;

@Data
public class AuthenticationRequest {
    private String userName;
    private String password;
}
