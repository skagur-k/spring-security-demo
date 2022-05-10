package com.skagur.jwtdemo.repository;

import com.skagur.jwtdemo.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

public interface UserRepository extends JpaRepository<User, Long> {
    User findByUsername(String username);
}
