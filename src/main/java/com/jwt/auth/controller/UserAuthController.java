package com.jwt.auth.controller;

import com.jwt.auth.domain.AppUser;
import com.jwt.auth.domain.AppUserRole;
import com.jwt.auth.domain.RoleUserDto;
import com.jwt.auth.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.net.URI;
import java.util.List;

@RestController
@RequestMapping("/auth")
public class UserAuthController {

    @Autowired
    private UserService userService;

    @GetMapping("/users")
    public ResponseEntity<List<AppUser>> getUsers() {
        return ResponseEntity.ok(userService.getUsers());
    }

    @PostMapping("/users")
    public ResponseEntity<AppUser> saveUser(@RequestBody AppUser appUser) {
        AppUser savedUser = userService.saveUser(appUser);
        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().toUriString());
        return ResponseEntity.created(uri).body(savedUser);
    }

    @PostMapping("/roles")
    public ResponseEntity<AppUserRole> saveRole(@RequestBody AppUserRole appUserRole) {
        AppUserRole userRole = userService.saveRole(appUserRole);
        return new ResponseEntity<>(userRole, HttpStatus.CREATED);
    }

    @PostMapping("/roles/add")
    public ResponseEntity<?> saveRoleToUser(@RequestBody RoleUserDto userRoleDto) {
        userService.addRoleToUser(userRoleDto.getUserName(), userRoleDto.getRoleName());
        return new ResponseEntity<>(HttpStatus.OK);
    }

    @GetMapping("/test")
    public String helloWorld() {
        return "Hello World!";
    }
}
