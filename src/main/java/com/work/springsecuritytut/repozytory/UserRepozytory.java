package com.work.springsecuritytut.repozytory;

import com.work.springsecuritytut.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepozytory extends JpaRepository<UserEntity,Long> {
    boolean existsByUsername(String username);
    Optional<UserEntity> findByEmail(String email);
}
