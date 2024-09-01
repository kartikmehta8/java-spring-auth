package com.auth.authentication.repository;

import com.auth.authentication.model.User;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.Optional;

public interface UserRepository extends MongoRepository<User, String> {
  Optional<User> findByEmail(String email);
}
