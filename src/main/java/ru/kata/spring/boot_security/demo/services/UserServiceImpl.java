package ru.kata.spring.boot_security.demo.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.kata.spring.boot_security.demo.models.Role;
import ru.kata.spring.boot_security.demo.models.User;
import ru.kata.spring.boot_security.demo.repository.RoleRepository;
import ru.kata.spring.boot_security.demo.repository.UserRepository;

import java.util.*;

@Service
@Transactional
public class UserServiceImpl implements UserService, UserDetailsService {

    private UserRepository userRepository;
    private RoleRepository roleRepository;


    @Autowired
    public UserServiceImpl(UserRepository userRepository, RoleRepository roleRepository) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
    }

    @Override
    public List<User> allUsers() {
        return userRepository.findAll();
    }

    @Override
    public void addUser(User user) {
        PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        userRepository.save(user);
    }

    @Override
    public void removeUser(Long id) {
        userRepository.deleteById(id);
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserDetails user = userRepository.getByUsername(username);
        if (user == null) {
            System.out.println(String.format("User was not found"));
            throw new UsernameNotFoundException(String.format("User was not found"));
        }
        return user;
    }

    @Override
    public List<Role> allRoles() {
        return roleRepository.findAll();
    }

    @Override
    public void saveAndFlush(User user) {
        userRepository.saveAndFlush(user);
    }

    @Override
    public Role findRoleById(Long roleId) {
        return roleRepository.findRoleById(roleId);
    }

    @Override
    public Set<Role> setRole(Long[] roleChoice) {
        Set<Role> roles = new HashSet<>();
        if (roleChoice != null) {
            for (long i : roleChoice) {
                roles.add(roleRepository.findRoleById(i));
            }
        } else {
            roles.add(roleRepository.findRoleById(2L));
        }
        return roles;
    }

    @Override
    public Set<Role> setRoleForEdition(Long[] roleChoice, User user) {
        Set<Role> roles = new HashSet<>();
        if (roleChoice != null) {
            for (long i : roleChoice) {
                roles.add(roleRepository.findRoleById(i));
            }
            return roles;
        } else {
            User editUser = userRepository.getById(user.getId());
            return editUser.getRoles();
        }
    }
}

