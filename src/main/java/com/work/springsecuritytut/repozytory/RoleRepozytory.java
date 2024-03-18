package com.work.springsecuritytut.repozytory;

import com.work.springsecuritytut.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.SimpleTimeZone;

public interface RoleRepozytory extends JpaRepository<Role,Long> {
    Optional<Role> findByName(String name);
}
