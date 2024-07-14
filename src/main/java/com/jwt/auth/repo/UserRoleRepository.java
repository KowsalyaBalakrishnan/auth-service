package com.jwt.auth.repo;

import com.jwt.auth.domain.AppUserRole;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRoleRepository extends JpaRepository<AppUserRole, Long> {

    AppUserRole findByName(String name);
}
