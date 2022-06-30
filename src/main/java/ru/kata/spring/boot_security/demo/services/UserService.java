package ru.kata.spring.boot_security.demo.services;

import org.springframework.security.core.userdetails.UserDetailsService;
import ru.kata.spring.boot_security.demo.models.Role;
import ru.kata.spring.boot_security.demo.models.User;

import java.util.List;
import java.util.Set;


public interface UserService extends UserDetailsService {
    List<User> allUsers();
    void addUser(User user);
    void removeUser(Long id);
    List<Role> allRoles();
    void saveAndFlush(User user);
    Role findRoleById(Long roleId);
}
