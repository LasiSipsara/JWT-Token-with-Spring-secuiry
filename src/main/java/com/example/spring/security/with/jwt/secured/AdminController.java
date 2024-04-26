package com.example.spring.security.with.jwt.secured;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/crackit/v1/admin")
@PreAuthorize("hasRole('ADMIN")
public class AdminController {
    @GetMapping
    @PreAuthorize("hasAuthority('admin:read')")
    public  String getAdmin(){
        return "Secured Endpoint::GET-Admin controller";
    }

    @GetMapping
    @PreAuthorize("hasAuthority('admin:create')")
    public  String post(){
        return "Secured Endpoint::POST-Admin controller";
    }


}
