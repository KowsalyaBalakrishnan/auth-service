package com.jwt.auth.service;

import com.jwt.auth.domain.AppUser;
import com.jwt.auth.domain.AppUserRole;

import java.util.List;

public interface UserService {

    AppUser saveUser(AppUser user);

    AppUserRole saveRole(AppUserRole role);

    void addRoleToUser(String userName, String roleName);

    AppUser getAppUser(String userName);

    List<AppUser> getUsers();
}
