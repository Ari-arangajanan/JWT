package com.ari.JWTProject.Spring.Security.JWT;

import com.ari.JWTProject.Spring.Security.JWT.requestAndResponce.AuthenticationRequest;
import com.ari.JWTProject.Spring.Security.JWT.requestAndResponce.AuthenticationResponce;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class Controller {

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserDetailsService userDetailsService;

    @Autowired
    JWTUtill jwtUtill;

    @RequestMapping(value = "/home",method = RequestMethod.GET)
    public String home(){
        return "<h1>Home</h1>";
    }

    @RequestMapping(value = "/user",method = RequestMethod.GET)
    public String user(){
        return "<h1>Home user</h1>";
    }

    @RequestMapping(value = "/admin",method = RequestMethod.GET)
    public String admin(){
        return "<h1>Home admin</h1>";
    }

    @RequestMapping(value = "/authenticate",method = RequestMethod.POST)
    public ResponseEntity<?> createAuthenticationToken(@RequestBody AuthenticationRequest authenticationRequest) throws Exception{
        try{
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                    authenticationRequest.getUserName(),authenticationRequest.getPassword()
            ));
        }catch (BadCredentialsException e){
            throw new Exception("incorrect UserName And PWD", e);
        }
        final UserDetails userDetails = userDetailsService.loadUserByUsername(
          authenticationRequest.getUserName()
        );
        final String jwt = jwtUtill.generateToken(userDetails);

        return ResponseEntity.ok(new AuthenticationResponce(jwt));
    }
}
