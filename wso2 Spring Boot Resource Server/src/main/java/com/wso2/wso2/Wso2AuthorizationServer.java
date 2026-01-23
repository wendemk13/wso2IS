package com.wso2.wso2;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;

@SpringBootApplication
@EnableMethodSecurity
public class Wso2AuthorizationServer {

    public static void main(String[] args) {
        SpringApplication.run(Wso2AuthorizationServer.class, args);
    }

}
