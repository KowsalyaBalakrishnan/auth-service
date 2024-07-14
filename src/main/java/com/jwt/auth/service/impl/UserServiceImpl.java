package com.jwt.auth.service.impl;

import com.jwt.auth.domain.AppUser;
import com.jwt.auth.domain.AppUserRole;
import com.jwt.auth.repo.UserRepository;
import com.jwt.auth.repo.UserRoleRepository;
import com.jwt.auth.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@Transactional
@Slf4j
public class UserServiceImpl implements UserService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private UserRoleRepository roleRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public AppUser saveUser(AppUser user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        log.info("Saving User to Database");
        return userRepository.save(user);
    }

    @Override
    public AppUserRole saveRole(AppUserRole role) {
        log.info("Saving Roles to Database");
        return roleRepository.save(role);
    }

    @Override
    public void addRoleToUser(String userName, String roleName) {
        log.info("Setting role = {} to User = {}", roleName, userName);
        AppUser userData = userRepository.findByUserName(userName);
        AppUserRole roleData = roleRepository.findByName(roleName);
        userData.getUserRoles().add(roleData);
    }

    @Override
    public AppUser getAppUser(String userName) {
        log.info("Getting app user information for the provided userName {}", userName);
        return userRepository.findByUserName(userName);
    }

    @Override
    public List<AppUser> getUsers() {
        log.info("Retrieving all users");
        return userRepository.findAll();
    }
}
