package com.binhan.registerapi.repository;

import com.binhan.registerapi.models.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<UserEntity,Long> {
    //Boolean existsByUsername(String username);
    Optional<UserEntity> findByUserName (String userName);
    //Optional<Object> findByUserName(String username);
}
