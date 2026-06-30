package com.example.userdetails.config;

import com.example.userdetails.model.User;
import com.example.userdetails.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class DataInitializer {
    @Bean
    public CommandLineRunner loadData(UserRepository repository) {
        return args -> {
            repository.save(new User("alice", "alice@example.com", "Alice", "Anderson"));
            repository.save(new User("bob", "bob@example.com", "Bob", "Brown"));
            repository.save(new User("carol", "carol@example.com", "Carol", "Clark"));
        };
    }
}
